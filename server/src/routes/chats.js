import { Router } from 'express';
import { z } from 'zod';
import { Message } from '../models/Message.js';
import { Group } from '../models/Group.js';
import { User } from '../models/User.js';
import { requireAuth } from '../middleware/auth.js';
import { asyncRoute, HttpError } from '../middleware/error.js';
import { directChatId, serialise } from './messages.js';
import { hasKeys } from './users.js';

const router = Router();

/**
 * GET /api/chats
 *
 * The chat list. Groups in one round-trip plus every 1:1 thread the user has
 * exchanged ciphertext with. Only the newest message per thread is returned,
 * and only in encrypted form.
 */
router.get(
  '/',
  requireAuth,
  asyncRoute(async (req, res) => {
    const me = String(req.user._id);
    // Clamped to a positive integer: a negative limit is not a smaller page, it is
    // an invalid argument that `.limit()` would reject outright.
    const requestedLimit = Number(req.query.limit);
    const limit = Number.isFinite(requestedLimit) && requestedLimit > 0
      ? Math.min(Math.floor(requestedLimit), 100)
      : 40;

    // Every group I belong to.
    const groups = await Group.find({ 'members.userId': me }).sort({ updatedAt: -1 }).limit(limit);
    const groupIds = groups.map((g) => g._id);
    const groupMemberIds = new Map(
      groups.map((g) => [String(g._id), g.members.map((m) => String(m.userId))]),
    );

    // Every direct thread I participate in. Chat ids are the two participant
    // ids sorted and joined with '|', so match the shape then filter in JS
    // rather than trying to express "either side is me" as a back-reference.
    const directChatIdPattern = /^[a-f\d]{24}\|[a-f\d]{24}$/i;
    const [directs, groupMessages] = await Promise.all([
      Message.find({ chatId: directChatIdPattern })
        .sort({ _id: -1 })
        .limit(2000),
      groupIds.length
        ? Message.find({ groupId: { $in: groupIds } }).sort({ _id: -1 }).limit(1000)
        : Promise.resolve([]),
    ]);

    // Keep only threads that actually include me.
    const myDirects = directs.filter((m) => m.chatId.split('|').includes(me));

    // Newest message per chat.
    const newest = new Map();
    for (const m of [...myDirects, ...groupMessages]) {
      if (!newest.has(m.chatId)) newest.set(m.chatId, m);
    }

    // Resolve peer profiles in one query.
    //
    // The string comparison has to be `String(m.receiverId) === me`. Written as
    // `m.receiverId === me`, the ObjectId is compared against a string, is
    // never equal, and the ternary below silently falls through to
    // `m.receiverId` - so the sender of a thread you started was reported as
    // their own peer.
    const peerIds = [
      ...new Set(
        myDirects.map((m) => (String(m.receiverId) === me ? m.senderId : m.receiverId)),
      ),
    ];
    const peers = await User.find({ _id: { $in: peerIds } })
      .select('displayName phone avatarColor lastSeenAt publicIdentityKey')
      .lean();
    const peerMap = new Map(peers.map((p) => [String(p._id), p]));

    const chats = [];
    for (const [chatId, m] of newest) {
      if (chatId.startsWith('group:')) {
        const gid = chatId.slice('group:'.length);
        const group = groups.find((g) => String(g._id) === gid);
        if (!group) continue;
        chats.push({
          chatId,
          type: 'group',
          groupId: gid,
          title: group.name,
          avatarColor: group.avatarColor,
          memberIds: groupMemberIds.get(gid) || [],
          disappearingMessagesSeconds: group.disappearingMessagesSeconds,
          lastMessage: compact(m),
        });
      } else {
        const otherId = String(m.senderId) === me ? String(m.receiverId) : String(m.senderId);
        const peer = peerMap.get(otherId);
        chats.push({
          chatId,
          type: 'direct',
          peerId: otherId,
          title: peer?.displayName || 'Unknown',
          phone: peer?.phone,
          avatarColor: peer?.avatarColor ?? 0,
          lastSeenAt: peer?.lastSeenAt,
          peerIdentityKey: peer?.publicIdentityKey,
          lastMessage: compact(m),
        });
      }
    }

    chats.sort((a, b) => new Date(b.lastMessage?.createdAt ?? 0) - new Date(a.lastMessage?.createdAt ?? 0));
    res.json({ chats: chats.slice(0, limit) });
  }),
);

/** GET /api/chats/:peerId - open (or create the view of) a 1:1 thread. */
router.get(
  '/with/:peerId',
  requireAuth,
  asyncRoute(async (req, res) => {
    if (!/^[a-f\d]{24}$/i.test(req.params.peerId)) {
      throw new HttpError(400, 'invalid_user_id', 'Malformed user id.');
    }
    const peer = await User.findById(req.params.peerId).select(
      'displayName phone avatarColor lastSeenAt publicIdentityKey',
    );
    if (!peer) throw new HttpError(404, 'user_not_found', 'No such user.');

    res.json({
      chatId: directChatId(req.user._id, peer._id),
      type: 'direct',
      peer: {
        id: String(peer._id),
        displayName: peer.displayName,
        phone: peer.phone,
        avatarColor: peer.avatarColor,
        lastSeenAt: peer.lastSeenAt,
        publicIdentityKey: peer.publicIdentityKey,
        hasKeys: hasKeys(peer.publicIdentityKey),
      },
    });
  }),
);

export default router;

function compact(m) {
  return {
    id: String(m._id),
    clientMessageId: m.clientMessageId,
    senderId: String(m.senderId),
    envelope: m.envelope,
    status: m.status,
    ciphertext: m.ciphertext,
    iv: m.iv,
    header: m.header,
    createdAt: m.createdAt,
    ...(m.groupId ? { groupId: String(m.groupId) } : {}),
  };
}
