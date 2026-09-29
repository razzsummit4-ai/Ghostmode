import { Router } from 'express';
import { z } from 'zod';
import { User } from '../models/User.js';
import { Message } from '../models/Message.js';
import { requireAuth } from '../middleware/auth.js';
import { asyncRoute, HttpError } from '../middleware/error.js';
import { zeroKnowledgeGuard } from '../middleware/zeroKnowledge.js';

const router = Router();

/**
 * GET /api/users/search?q=
 *
 * Directory search by phone number. The response is deliberately limited to
 * the fields a client needs to start an X3DH handshake.
 */
router.get(
  '/search',
  requireAuth,
  asyncRoute(async (req, res) => {
    const q = String(req.query.q || '').trim();
    if (q.length < 3) {
      throw new HttpError(400, 'query_too_short', 'Provide at least 3 characters.');
    }
    // Match on phone digits; allow a spaced/dashed human-entered format.
    const digits = q.replace(/[^\d]/g, '');
    const filter = digits.length >= 3
      ? { phone: { $regex: `${escapeRegex(digits)}` } }
      : { displayName: { $regex: escapeRegex(q), $options: 'i' } };

    const users = await User.find(filter)
      .select('phone displayName publicIdentityKey registrationId avatarColor lastSeenAt')
      .limit(20);

    res.json({
      users: users.map((u) => ({
        id: String(u._id),
        phone: u.phone,
        displayName: u.displayName,
        publicIdentityKey: u.publicIdentityKey,
        registrationId: u.registrationId,
        avatarColor: u.avatarColor,
        lastSeenAt: u.lastSeenAt,
        hasKeys: hasKeys(u.publicIdentityKey),
      })),
    });
  }),
);

/** GET /api/users/:id - public profile. */
router.get(
  '/:id',
  requireAuth,
  asyncRoute(async (req, res) => {
    if (!/^[a-f\d]{24}$/i.test(req.params.id)) {
      throw new HttpError(400, 'invalid_user_id', 'Malformed user id.');
    }
    const user = await User.findById(req.params.id).select(
      'phone displayName publicIdentityKey registrationId avatarColor lastSeenAt',
    );
    if (!user) throw new HttpError(404, 'user_not_found', 'No such user.');
    res.json({
      user: {
        id: String(user._id),
        phone: user.phone,
        displayName: user.displayName,
        publicIdentityKey: user.publicIdentityKey,
        registrationId: user.registrationId,
        avatarColor: user.avatarColor,
        lastSeenAt: user.lastSeenAt,
        hasKeys: hasKeys(user.publicIdentityKey),
      },
    });
  }),
);

/**
 * GET /api/users/:id/keys
 *
 * Safety-number helper. The server concatenates the two public identity keys
 * and hashes them; it has no private key and therefore cannot forge a
 * comparison. Clients verify the digits shown here against the peer's own
 * independently computed value.
 */
router.get(
  '/:id/safety-number',
  requireAuth,
  zeroKnowledgeGuard(),
  asyncRoute(async (req, res) => {
    if (!/^[a-f\d]{24}$/i.test(req.params.id)) {
      throw new HttpError(400, 'invalid_user_id', 'Malformed user id.');
    }
    const [me, peer] = await Promise.all([
      User.findById(req.user._id).select('publicIdentityKey'),
      User.findById(req.params.id).select('publicIdentityKey displayName phone'),
    ]);
    if (!peer) throw new HttpError(404, 'user_not_found', 'No such user.');
    if (peer.publicIdentityKey === null) {
      throw new HttpError(409, 'peer_has_no_keys', 'That device has not published keys yet.');
    }

    res.json({
      userId: String(peer._id),
      displayName: peer.displayName,
      // Raw hashes; the client renders the 60-digit / 12-group fingerprint.
      localIdentityKey: me.publicIdentityKey,
      remoteIdentityKey: peer.publicIdentityKey,
    });
  }),
);

/** GET /api/users/:id/conversations - chat metadata for the list screen. */
router.get(
  '/:id/conversations',
  requireAuth,
  asyncRoute(async (req, res) => {
    const [a, b] = [String(req.user._id), req.params.id].sort();
    const chatId = `${a}|${b}`;
    const [peer, last] = await Promise.all([
      User.findById(req.params.id).select('displayName phone avatarColor lastSeenAt publicIdentityKey'),
      Message.findOne({ chatId }).sort({ _id: -1 }),
    ]);
    if (!peer) throw new HttpError(404, 'user_not_found', 'No such user.');
    res.json({
      chatId,
      peer: {
        id: String(peer._id),
        displayName: peer.displayName,
        phone: peer.phone,
        avatarColor: peer.avatarColor,
        lastSeenAt: peer.lastSeenAt,
        publicIdentityKey: peer.publicIdentityKey,
      },
      // Ciphertext only - the client decrypts it locally.
      lastMessage: last
        ? {
            id: String(last._id),
            senderId: String(last.senderId),
            envelope: last.envelope,
            status: last.status,
            createdAt: last.createdAt,
            ciphertext: last.ciphertext,
            iv: last.iv,
            header: last.header,
          }
        : null,
    });
  }),
);

export default router;

/** A device has published keys once an identity key is present. */
export function hasKeys(identityKey) {
  return typeof identityKey === 'string' && identityKey.length > 0;
}

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
