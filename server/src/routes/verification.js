import { Router } from 'express';
import crypto from 'node:crypto';
import { z } from 'zod';
import { User } from '../models/User.js';
import { requireAuth } from '../middleware/auth.js';
import { asyncRoute, HttpError } from '../middleware/error.js';
import { zeroKnowledgeGuard } from '../middleware/zeroKnowledge.js';
import { logger } from '../logger.js';

const router = Router();

/**
 * An alphabet with no confusable characters.
 *
 * A code gets read aloud and typed by hand, so O/0 and I/l are deliberately
 * absent - they are the characters people get wrong, and a mistyped code that
 * is rejected with no hint is indistinguishable from a wrong one.
 */
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const CODE_GROUPS = 3;
const CODE_GROUP_LEN = 4;

/** Format a raw code as XXXX-XXXX-XXXX. */
function formatCode(raw) {
  return (raw.match(/.{1,4}/g) ?? []).join('-');
}

/**
 * Reduce whatever a human typed to the canonical form.
 *
 * Case, spaces and dashes are the only things a person adds by accident, so
 * those are stripped. The look-alike characters need no mapping: the alphabet
 * deliberately contains neither O/0 nor I/l, so a code can never hold a
 * character that has a twin, and typing one is simply a wrong character rather
 * than a subtly different code.
 */
function normaliseCode(input) {
  return String(input ?? '').toUpperCase().replace(/[^A-Z0-9]/g, '');
}

function generateCode() {
  const total = CODE_GROUPS * CODE_GROUP_LEN;
  // Rejection sampling, so every character is uniformly distributed. A plain
  // modulo over a 32-character alphabet would bias the first few letters.
  const out = [];
  while (out.length < total) {
    for (const byte of crypto.randomBytes(total)) {
      if (byte >= 256 - (256 % ALPHABET.length)) continue;
      out.push(ALPHABET[byte % ALPHABET.length]);
      if (out.length === total) break;
    }
  }
  return formatCode(out.join(''));
}

/** Compare in constant time so a wrong code leaks nothing by timing. */
function codesMatch(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  if (x.length !== y.length) return false;
  return crypto.timingSafeEqual(x, y);
}

/**
 * GET /api/verification/code
 *
 * The account's own code, or `{ code: null }` when none has been created.
 */
router.get(
  '/code',
  requireAuth,
  asyncRoute(async (req, res) => {
    const user = await User.findById(req.user._id).select('+verificationCode');
    res.json({ code: user.verificationCode ?? null });
  }),
);

/**
 * POST /api/verification/code
 *
 * Create the code, or replace it with `rotate: true`.
 */
router.post(
  '/code',
  requireAuth,
  asyncRoute(async (req, res) => {
    const body = z.object({ rotate: z.boolean().optional().default(false) }).parse(req.body ?? {});

    const user = await User.findById(req.user._id).select('+verificationCode');
    if (user.verificationCode && !body.rotate) {
      return res.json({ code: user.verificationCode, created: false });
    }

    user.verificationCode = generateCode();
    await user.save();

    logger.info('verification.code_set', {
      userId: String(user._id),
      rotated: Boolean(body.rotate),
    });
    // The code itself is never logged.
    res.json({ code: user.verificationCode, created: true });
  }),
);

/**
 * GET /api/verification/:userId
 *
 * Whether this account may open a conversation with `userId`. Deliberately
 * does not reveal the peer's code, only whether access has been granted.
 */
router.get(
  '/:userId',
  requireAuth,
  asyncRoute(async (req, res) => {
    const { userId } = req.params;
    if (!/^[a-f\d]{24}$/i.test(userId)) {
      throw new HttpError(400, 'invalid_user_id', 'Malformed user id.');
    }
    const me = await User.findById(req.user._id).select('verifiedPeers');
    res.json({
      userId,
      verified: me.verifiedPeers.some((id) => String(id) === userId),
    });
  }),
);

/**
 * POST /api/verification/:userId
 *
 * Submit the code belonging to `userId`. Access is granted only on an exact
 * match, and a wrong code is reported identically whether the account exists,
 * has no code, or the code is simply wrong - otherwise this endpoint would
 * confirm which phone numbers have set one up.
 */
router.post(
  '/:userId',
  requireAuth,
  zeroKnowledgeGuard({ allowFields: ['code'] }),
  asyncRoute(async (req, res) => {
    const { userId } = req.params;
    if (!/^[a-f\d]{24}$/i.test(userId)) {
      throw new HttpError(400, 'invalid_user_id', 'Malformed user id.');
    }
    const { code } = z.object({ code: z.string().min(4).max(32) }).parse(req.body);

    const peer = await User.findById(userId).select('+verificationCode');
    const me = await User.findById(req.user._id).select('verifiedPeers');

    const offered = normaliseCode(code);
    const correct = peer?.verificationCode ? normaliseCode(peer.verificationCode) : null;

    if (!correct || !codesMatch(offered, correct)) {
      logger.warn('verification.code_rejected', { peerId: userId });
      throw new HttpError(
        403,
        'verification_failed',
        'That code is not correct. Ask the person for the code they created in '
        + 'their profile, then enter it exactly as they gave it to you.',
      );
    }

    if (!me.verifiedPeers.some((id) => String(id) === userId)) {
      me.verifiedPeers.push(peer._id);
      await me.save();
    }

    logger.info('verification.granted', { userId: String(me._id), peerId: userId });
    res.json({ userId, verified: true });
  }),
);

/**
 * DELETE /api/verification/:userId
 *
 * Withdraw access to a peer. They keep their own code; this only revokes what
 * this account had granted itself.
 */
router.delete(
  '/:userId',
  requireAuth,
  asyncRoute(async (req, res) => {
    const { userId } = req.params;
    const me = await User.findById(req.user._id).select('verifiedPeers');
    me.verifiedPeers = me.verifiedPeers.filter((id) => String(id) !== userId);
    await me.save();
    res.json({ userId, verified: false });
  }),
);

export default router;