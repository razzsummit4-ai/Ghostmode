import { Router } from 'express';
import { z } from 'zod';
import { Message } from '../models/Message.js';
import { Group } from '../models/Group.js';
import { User } from '../models/User.js';
import { requireAuth } from '../middleware/auth.js';
import { asyncRoute, HttpError } from '../middleware/error.js';
import { messageLimiter } from '../middleware/rateLimit.js';
import { zeroKnowledgeGuard, zeroKnowledgeHandler } from '../middleware/zeroKnowledge.js';
import { logger } from '../logger.js';

const router = Router();

/** Deterministic chat id for a 1:1 conversation, independent of who asks. */
export function directChatId(a, b) {
  return [String(a), String(b)].sort().join('|');
}

const isId = (s) => /^[a-f\d]{24}$/i.test(String(s));

const ciphertext = z.string().min(1).max(200_000);
const iv = z.string().min(1).max(64).regex(/^[A-Za-z0-9+/=_-]+$/, 'must be base64');

const headerSchema = z.object({
  type: z.enum(['prekey', 'msg', 'groupkey', 'group']),
  preKeyId: z.number().int().nonnegative().nullish(),
  signedPreKeyId: z.number().int().nonnegative().nullish(),
  baseKey: z.string().max(128).nullish(),
  ratchetKey: z.string().max(128).nullish(),
  counter: z.number().int().nonnegative().nullish(),
  previousCounter: z.number().int().nonnegative().nullish(),
  senderKeyId: z.string().max(128).nullish(),
  senderChainId: z.number().int().nonnegative().nullish(),
  senderIteration: z.number().int().nonnegative().nullish(),
});

const envelopeSchema = z.object({
  // Coarse routing hint so the UI can show a placeholder before decrypting.
  // It carries no message content.
  type: z.enum(['text', 'media', 'key', 'system']).default('text'),
  attachmentCount: z.number().int().min(0).max(10).default(0),
  expiresInSeconds: z.number().int().min(0).max(60 * 60 * 24 * 30).default(0),
});

/**
 * POST /api/messages
 *
 * Body: { clientMessageId, receiverId|groupId, ciphertext, iv, mac?, header, envelope }
 *
 * There is deliberately no `text` / `body` / `plaintext` field. The
 * zero-knowledge guard rejects such a request outright, and the Mongoose
 * schema is `strict: 'throw'`, so nothing could be persisted regardless.
 */
const sendSchema = z
  .object({
    clientMessageId: z.string().min(8).max(64),
    receiverId: z.string().regex(/^[a-f\d]{24}$/i).optional(),
    groupId: z.string().regex(/^[a-f\d]{24}$/i).optional(),
    ciphertext,
    iv,
    mac: z.string().max(128).optional().default(''),
    header: headerSchema,
    envelope: envelopeSchema,
    replyToClientMessageId: z.string().max(64).optional(),
  })
  .refine((b) => Boolean(b.receiverId) !== Boolean(b.groupId), {
    message: 'Provide exactly one of receiverId or groupId.',
  });


router.post(
  '/',
  requireAuth,
  messageLimiter,
  zeroKnowledgeGuard(),
  zeroKnowledgeHandler(async (req, res) => {
    const body = sendSchema.parse(req.body);
    const sender = req.user;

    let conversationType = 'direct';
    let chatId;
    let receiverId = null;
    let group = null;
    let expiresInSeconds = body.envelope.expiresInSeconds;

    if (body.groupId) {
      group = await Group.findById(body.groupId);
      if (!group) throw new HttpError(404, 'group_not_found', 'No such group.');
      if (!group.members.some((m) => String(m.userId) === String(sender._id))) {
        throw new HttpError(403, 'not_a_member', 'You are not a member of this group.');
      }
      conversationType = 'group';
      chatId = `group:${group._id}`;
      if (!expiresInSeconds) expiresInSeconds = group.disappearingMessagesSeconds || 0;
    } else {
      const target = await User.findById(body.receiverId).select('_id');
      if (!target) throw new HttpError(404, 'receiver_not_found', 'No such recipient.');
      if (String(target._id) === String(sender._id)) {
        throw new HttpError(400, 'cannot_message_self', 'You cannot message yourself.');
      }
      receiverId = target._id;
      chatId = directChatId(sender._id, target._id);
    }

    // Idempotency: a retried send with the same clientMessageId returns the
    // original document instead of duplicating the message.
    const existing = await Message.findOne({
      senderId: sender._id,
      clientMessageId: body.clientMessageId,
    });
    if (existing) {
      res.status(200).json({ message: serialise(existing), duplicate: true });
      return;
    }

    const expiresAt = expiresInSeconds > 0 ? new Date(Date.now() + expiresInSeconds * 1000) : null;

    const message = await Message.create({
      clientMessageId: body.clientMessageId,
      chatId,
      conversationType,
      senderId: sender._id,
      receiverId,
      groupId: group?._id ?? null,
      ciphertext: body.ciphertext,
      iv: body.iv,
      mac: body.mac,
      header: body.header,
      envelope: { ...body.envelope, expiresInSeconds },
      expiresAt,
      replyToClientMessageId: body.replyToClientMessageId ?? null,
      status: 'sent',
    });

    logger.info('message.stored', {
      messageId: String(message._id),
      chatId,
      conversationType,
      senderId: String(sender._id),
      bytes: body.ciphertext.length,
      expiresInSeconds,
    });

    // Real-time delivery is handled by the Socket.io gateway via an in-process
    // handle, so the HTTP layer stays transport-agnostic.
    req.app.get('io')?.to(deliveryTargets(sender._id, receiverId, group)).emit('message:new', {
      message: serialise(message),
    });

    res.status(201).json({ message: serialise(message), duplicate: false });
  }),
);

/** GET /api/messages/:chatId?limit=&before=&after= */
router.get(
  '/:chatId',
  requireAuth,
  asyncRoute(async (req, res) => {
    const { chatId } = req.params;
    await assertChatAccess(chatId, req.user);

    // A negative or NaN limit must not reach the driver: `.limit(-5)` throws,
    // which surfaces as a 500 rather than the 400 the client deserves.
    const requested = Number(req.query.limit);
    const limit = Number.isFinite(requested) && requested > 0
      ? Math.min(Math.floor(requested), 200)
      : 50;
    const query = { chatId };

    // Keyset pagination on _id rather than skip/limit, which degrades the
    // deeper you page and can duplicate rows under concurrent writes.
    //
    // The cursors go into a Mongo comparison, so they must be validated here:
    // an unvalidated value reaches the driver as a CastError, which the error
    // handler reports as an opaque 500 instead of the 400 the client sent
    // something wrong.
    if (req.query.before !== undefined) {
      if (!isId(req.query.before)) {
        throw new HttpError(400, 'invalid_cursor', 'Malformed "before" cursor.');
      }
      query._id = { $lt: req.query.before };
    }
    if (req.query.after !== undefined) {
      if (!isId(req.query.after)) {
        throw new HttpError(400, 'invalid_cursor', 'Malformed "after" cursor.');
      }
      query._id = query._id ? { ...query._id, $gt: req.query.after } : { $gt: req.query.after };
    }

    const messages = await Message.find(query).sort({ _id: -1 }).limit(limit);
    const nextCursor = messages.length === limit ? String(messages[messages.length - 1]._id) : null;

    res.json({
      messages: messages.map(serialise).reverse(),
      nextCursor,
      hasMore: messages.length === limit,
    });
  }),
);

/**
 * POST /api/messages/status
 * Body: { messageIds: [...], status: 'delivered' | 'read' }
 * Batched so opening a chat is one round-trip, not one per message.
 */
router.post(
  '/status',
  requireAuth,
  asyncRoute(async (req, res) => {
    const body = z
      .object({
        messageIds: z.array(z.string().regex(/^[a-f\d]{24}$/i)).min(1).max(500),
        status: z.enum(['delivered', 'read']),
      })
      .parse(req.body);

    const now = new Date();
    const set =
      body.status === 'read' ? { status: 'read', readAt: now } : { status: 'delivered', deliveredAt: now };

    // Scope strictly to messages addressed to this user, so nobody can mark
    // somebody else's thread as read.
    const result = await Message.updateMany(
      { _id: { $in: body.messageIds }, receiverId: req.user._id, senderId: { $ne: req.user._id } },
      { $set: set },
    );

    // Notify each distinct sender.
    const senders = await Message.find({ _id: { $in: body.messageIds } })
      .select('senderId')
      .lean();
    const io = req.app.get('io');
    if (io) {
      const rooms = [...new Set(senders.map((m) => `user:${m.senderId}`))];
      io.to(rooms).emit(`message:${body.status}`, {
        messageIds: body.messageIds,
        by: String(req.user._id),
        at: now.toISOString(),
      });
    }

    res.json({ updated: result.modifiedCount, status: body.status });
  }),
);

/** DELETE /api/messages/:id - remove a message you sent. */
router.delete(
  '/:id',
  requireAuth,
  asyncRoute(async (req, res) => {
    if (!isId(req.params.id)) throw new HttpError(400, 'invalid_id', 'Malformed message id.');
    const message = await Message.findById(req.params.id);
    if (!message) throw new HttpError(404, 'not_found', 'No such message.');
    if (String(message.senderId) !== String(req.user._id)) {
      throw new HttpError(403, 'forbidden', 'You can only delete your own messages.');
    }
    await Message.deleteOne({ _id: message._id });
    logger.info('message.deleted', { messageId: String(message._id) });
    res.json({ deleted: true });
  }),
);

export default router;

/** Socket.io rooms that should receive a newly stored message. */
function deliveryTargets(senderId, receiverId, group) {
  const rooms = [`user:${senderId}`];
  if (receiverId) rooms.push(`user:${receiverId}`);
  if (group) for (const m of group.members) rooms.push(`user:${m.userId}`);
  return rooms;
}

/** Client-facing message shape. Ciphertext only - nothing decryptable. */
export function serialise(m) {
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
    deliveredAt: m.deliveredAt,
    readAt: m.readAt,
    expiresAt: m.expiresAt,
    replyToClientMessageId: m.replyToClientMessageId,
    createdAt: m.createdAt,
  };
}

/** Reject reads/writes to a chat the caller does not belong to. */
async function assertChatAccess(chatId, user) {
  if (String(chatId).startsWith('group:')) {
    const groupId = String(chatId).slice('group:'.length);
    if (!isId(groupId)) throw new HttpError(400, 'invalid_chat_id', 'Malformed chat id.');
    const group = await Group.findById(groupId).select('members').lean();
    if (!group) throw new HttpError(404, 'group_not_found', 'No such group.');
    if (!group.members.some((m) => String(m.userId) === String(user._id))) {
      throw new HttpError(403, 'not_a_member', 'You are not a member of this group.');
    }
    return;
  }
  const parts = String(chatId).split('|');
  if (parts.length !== 2 || !parts.every(isId)) {
    throw new HttpError(400, 'invalid_chat_id', 'Malformed chat id.');
  }
  if (!parts.includes(String(user._id))) {
    throw new HttpError(403, 'forbidden', 'You are not a participant in this chat.');
  }
}

