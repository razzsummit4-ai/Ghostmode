import { Server } from 'socket.io';
import { authenticateHandshake } from '../middleware/auth.js';
import { assertNoPlaintext, assertPublicOnly } from '../lib/zero-knowledge.js';
import { User } from '../models/User.js';
import { logger } from '../logger.js';
import { config } from '../config.js';

/**
 * Realtime gateway.
 *
 * Every inbound payload passes the same zero-knowledge guard as the REST API:
 * a client that tries to push plaintext over the socket is refused rather than
 * trusted. The gateway relays ciphertext and presence only - it never stores
 * or inspects message content.
 */
export function attachSocketGateway(httpServer, app) {
  const io = new Server(httpServer, {
    cors: { origin: config.CORS_ORIGINS, credentials: false },
    // Cap frames so one client cannot exhaust server memory.
    maxHttpBufferSize: 1e6,
    pingInterval: 25_000,
    pingTimeout: 20_000,
  });

  // Share the io instance with the HTTP layer (used to fan out new messages).
  app.set('io', io);

  io.use(async (socket, next) => {
    try {
      socket.data.user = await authenticateHandshake(socket.handshake.auth);
      next();
    } catch (err) {
      logger.warn('socket.auth_failed', { reason: err.message });
      next(Object.assign(new Error('unauthorized'), { data: { code: 'unauthorized' } }));
    }
  });

  io.on('connection', (socket) => {
    const user = socket.data.user;
    socket.join(`user:${user._id}`);
    User.updateOne({ _id: user._id }, { $set: { lastSeenAt: new Date() } }).catch(() => {});

    logger.info('socket.connected', {
      userId: String(user._id),
      preKeysLeft: user.oneTimePreKeys.length,
    });

    /**
     * Persisting messages goes through POST /api/messages so there is exactly
     * one code path that touches the database. The socket only fans out.
     */
    socket.on('message:send', (ack) => {
      if (typeof ack === 'function') {
        ack({
          ok: false,
          error: 'use_http',
          message: 'Persist via POST /api/messages; the socket then fans the message out.',
        });
      }
    });

    /** Typing indicator. Never carries content. */
    socket.on('typing', (payload = {}) => {
      try {
        assertNoPlaintext(payload);
        const { receiverId, groupId, typing } = payload;
        if (groupId) {
          socket.to(`group:${groupId}`).emit('typing', {
            groupId,
            userId: String(user._id),
            typing: Boolean(typing),
          });
        } else if (typeof receiverId === 'string') {
          io.to(`user:${receiverId}`).emit('typing', {
            receiverId,
            userId: String(user._id),
            typing: Boolean(typing),
          });
        }
      } catch {
        logger.warn('socket.typing_rejected', { userId: String(user._id) });
        socket.emit('error:zk', { message: 'Typing payload rejected by the zero-knowledge guard.' });
      }
    });


    /** Delivery / read receipts. */
    socket.on('receipt', (payload = {}, ack) => {
      try {
        assertNoPlaintext(payload);
        const { messageIds, status, senderId } = payload;
        if (!Array.isArray(messageIds) || !['delivered', 'read'].includes(status)) {
          throw new Error('bad receipt shape');
        }
        if (typeof senderId !== 'string' || senderId === String(user._id)) {
          throw new Error('cannot receipt your own messages');
        }
        io.to(`user:${senderId}`).emit(
          status === 'read' ? 'message:read' : 'message:delivered',
          { messageIds, by: String(user._id), at: new Date().toISOString() },
        );
        if (typeof ack === 'function') ack({ ok: true });
      } catch (err) {
        logger.warn('socket.receipt_rejected', { userId: String(user._id) });
        if (typeof ack === 'function') ack({ ok: false, error: err.message });
      }
    });

    /** Join a group room for typing fan-out. Membership is verified. */
    socket.on('group:join', async ({ groupId } = {}, ack) => {
      try {
        assertPublicOnly({ groupId });
        const { Group } = await import('../models/Group.js');
        const group = await Group.findById(groupId).select('members').lean();
        if (!group || !group.members.some((m) => String(m.userId) === String(user._id))) {
          throw new Error('not_a_member');
        }
        socket.join(`group:${groupId}`);
        if (typeof ack === 'function') ack({ ok: true });
      } catch (err) {
        if (typeof ack === 'function') ack({ ok: false, error: err.message });
      }
    });

    /** Leave a group room, so typing fan-out stops for a group the user left. */
    socket.on('group:leave', ({ groupId } = {}) => {
      if (typeof groupId === 'string' && groupId) socket.leave(`group:${groupId}`);
    });

    /** Redeliver anything missed while the client was offline. */
    socket.on('sync:request', async ({ after } = {}, ack) => {
      try {
        const { Message } = await import('../models/Message.js');
        const { Group } = await import('../models/Group.js');
        const myGroups = await Group.find({ 'members.userId': user._id }).select('_id').lean();
        // An absent or unparseable cursor means "everything", so a device that
        // has never synced still receives its backlog.
        const since = new Date(after || 0);
        const cutoff = Number.isNaN(since.getTime()) ? new Date(0) : since;
        const messages = await Message.find({
          createdAt: { $gt: cutoff },
          $or: [
            { receiverId: user._id },
            { groupId: { $in: myGroups.map((g) => g._id) } },
          ],
        })
          .sort({ _id: 1 })
          .limit(500);

        socket.emit('sync:batch', { messages: messages.map(toWire) });
        if (typeof ack === 'function') ack({ ok: true, count: messages.length });
      } catch (err) {
        if (typeof ack === 'function') ack({ ok: false, error: err.message });
      }
    });

    socket.on('disconnect', (reason) => {
      logger.info('socket.disconnected', { userId: String(user._id), reason });
    });
  });

  logger.info('socket.ready');
  return io;
}

/** Wire shape for a message - ciphertext only, never plaintext. */
function toWire(m) {
  return {
    id: String(m._id),
    clientMessageId: m.clientMessageId,
    chatId: m.chatId,
    conversationType: m.conversationType,
    senderId: String(m.senderId),
    receiverId: m.receiverId ? String(m.receiverId) : null,
    groupId: m.groupId ? String(m.groupId) : null,
    ciphertext: m.ciphertext,
    iv: m.iv,
    mac: m.mac,
    header: m.header,
    envelope: m.envelope,
    status: m.status,
    createdAt: m.createdAt,
  };
}