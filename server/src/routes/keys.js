import { Router } from 'express';
import { z } from 'zod';
import { User } from '../models/User.js';
import { requireAuth } from '../middleware/auth.js';
import { asyncRoute, HttpError } from '../middleware/error.js';
import { zeroKnowledgeGuard, zeroKnowledgeHandler } from '../middleware/zeroKnowledge.js';
import { hasKeys } from './users.js';
import { logger } from '../logger.js';

const router = Router();

const b64 = z.string().min(1).max(512).regex(/^[A-Za-z0-9+/=_-]+$/, 'must be base64');

const publishSchema = z.object({
  identityKey: b64.describe('Ed25519 identity public key'),
  signedPreKey: z.object({
    keyId: z.number().int().nonnegative(),
    publicKey: b64.describe('X25519 signed pre-key public half'),
    signature: b64.describe('Ed25519 signature over signedPreKey.publicKey'),
  }),
  oneTimePreKeys: z
    .array(z.object({ keyId: z.number().int().nonnegative(), publicKey: b64 }))
    .min(1)
    .max(200),
  deviceName: z.string().max(80).optional(),
  deviceId: z.string().max(64).optional(),
});

/** Decode and sanity-check a base64 key of an expected byte length. */
function decodeKey(value, expectedBytes, label) {
  const buf = Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  if (buf.length !== expectedBytes) {
    throw new HttpError(
      400,
      'invalid_key_length',
      `${label} must be ${expectedBytes} bytes when base64-decoded, got ${buf.length}.`,
    );
  }
  return buf;
}

const isValidId = (id) => /^[a-f\d]{24}$/i.test(String(id));

/**
 * POST /api/keys
 *
 * Publishes this device's PUBLIC key bundle. The zero-knowledge guard rejects
 * any body containing a private key, so a compromised or buggy client
 * physically cannot leak one here.
 */
router.post(
  '/',
  requireAuth,
  zeroKnowledgeGuard(),
  zeroKnowledgeHandler(async (req, res) => {
    const body = publishSchema.parse(req.body);

    // Validate key sizes before storing anything.
    decodeKey(body.identityKey, 32, 'identityKey');
    decodeKey(body.signedPreKey.publicKey, 32, 'signedPreKey.publicKey');
    decodeKey(body.signedPreKey.signature, 64, 'signedPreKey.signature');
    for (const k of body.oneTimePreKeys) decodeKey(k.publicKey, 32, `oneTimePreKeys[${k.keyId}]`);

    const user = req.user;
    const now = new Date();
    user.publicIdentityKey = body.identityKey;
    user.signedPreKey = { ...body.signedPreKey, createdAt: now };
    user.oneTimePreKeys = body.oneTimePreKeys.map((k) => ({ ...k, createdAt: now }));
    if (body.deviceName) user.deviceName = body.deviceName;
    if (body.deviceId) user.deviceId = body.deviceId;
    // A fresh identity key means a new registration id, per the Signal spec.
    user.registrationId = Math.floor(Math.random() * 0x3fffffff);
    user.consumedOneTimePreKeys = [];
    await user.save();

    logger.info('keys.published', {
      userId: String(user._id),
      preKeyCount: body.oneTimePreKeys.length,
      signedPreKeyId: body.signedPreKey.keyId,
    });

    res.status(201).json({
      ok: true,
      registrationId: user.registrationId,
      preKeyCount: user.oneTimePreKeys.length,
    });
  }),
);

/** POST /api/keys/prekeys - replenish the one-time pre-key pool. */
router.post(
  '/prekeys',
  requireAuth,
  zeroKnowledgeGuard(),
  zeroKnowledgeHandler(async (req, res) => {
    const schema = z.object({
      oneTimePreKeys: z
        .array(z.object({ keyId: z.number().int().nonnegative(), publicKey: b64 }))
        .min(1)
        .max(200),
    });
    const { oneTimePreKeys } = schema.parse(req.body);
    for (const k of oneTimePreKeys) decodeKey(k.publicKey, 32, `oneTimePreKeys[${k.keyId}]`);

    const user = req.user;

    // Refuse a top-up that re-uses an id the pool already holds, and refuse a
    // batch that collides with itself.
    //
    // A duplicate keyId makes the pool ambiguous: the server would hand out an
    // id whose public key no longer corresponds to the private half the
    // responder recovers locally under that same id. The handshake would then
    // derive a different shared secret and every message in that session would
    // fail its GCM tag with no useful error. The server cannot tell whether an
    // id is *correct*, only whether it is *ambiguous*, so this is the one part
    // of the failure it can actually stop.
    const existingIds = new Set(user.oneTimePreKeys.map((k) => k.keyId));
    const incomingIds = new Set();
    for (const k of oneTimePreKeys) {
      if (existingIds.has(k.keyId) || incomingIds.has(k.keyId)) {
        throw new HttpError(
          409,
          'prekey_id_collision',
          `One-time pre-key ${k.keyId} is already published. Ids must keep increasing.`,
        );
      }
      incomingIds.add(k.keyId);
    }

    const merged = [
      ...user.oneTimePreKeys,
      ...oneTimePreKeys.map((k) => ({ ...k, createdAt: new Date() })),
    ];
    merged.sort((a, b) => a.keyId - b.keyId);
    // Cap the pool, keeping the highest ids.
    user.oneTimePreKeys = merged.slice(-150);
    await user.save();
    res.json({ ok: true, preKeyCount: user.oneTimePreKeys.length });
  }),
);


/**
 * GET /api/keys/:userId[?consume=true]
 *
 * Without `consume`, a directory lookup: identity key + signed pre-key.
 * With `consume=true`, atomically burns exactly one one-time pre-key so it can
 * be used for an X3DH handshake and can never be replayed.
 */
router.get(
  '/:userId',
  requireAuth,
  asyncRoute(async (req, res) => {
    const { userId } = req.params;
    if (!isValidId(userId)) {
      throw new HttpError(400, 'invalid_user_id', 'Malformed user id.');
    }

    const target = await User.findById(userId);
    if (!target) throw new HttpError(404, 'user_not_found', 'No such user.');

    // A device may be authenticated but not yet have generated its key bundle.
    if (!hasKeys(target.publicIdentityKey) || !target.signedPreKey?.publicKey) {
      throw new HttpError(
        409,
        'keys_not_published',
        'That device has not published its key bundle yet.',
      );
    }

    if (req.query.consume !== 'true') {
      res.json({
        userId: String(target._id),
        phone: target.phone,
        displayName: target.displayName,
        publicIdentityKey: target.publicIdentityKey,
        registrationId: target.registrationId,
        signedPreKey: {
          keyId: target.signedPreKey.keyId,
          publicKey: target.signedPreKey.publicKey,
          signature: target.signedPreKey.signature,
        },
        preKeyCount: target.oneTimePreKeys.length,
        lastSeenAt: target.lastSeenAt,
      });
      return;
    }

    if (String(target._id) === String(req.user._id)) {
      throw new HttpError(400, 'cannot_consume_own_prekey', 'You cannot consume your own pre-key.');
    }
    if (target.oneTimePreKeys.length === 0) {
      throw new HttpError(409, 'no_prekeys_available', 'The device has no one-time pre-keys left.');
    }

    // Atomically pop the lowest-id unconsumed pre-key. Matching on keyId in the
    // filter guarantees two concurrent handshakes can never receive the same
    // one-time key.
    const preKey = target.oneTimePreKeys[0];
    const updated = await User.findOneAndUpdate(
      { _id: target._id, 'oneTimePreKeys.keyId': preKey.keyId },
      {
        $pull: { oneTimePreKeys: { keyId: preKey.keyId } },
        $push: {
          consumedOneTimePreKeys: {
            keyId: preKey.keyId,
            publicKey: preKey.publicKey,
            consumedAt: new Date(),
            consumedBy: req.user._id,
          },
        },
      },
      { new: true },
    );

    if (!updated) throw new HttpError(409, 'prekey_race', 'Pre-key taken by another session, retry.');

    logger.info('keys.consumed', {
      consumerId: String(req.user._id),
      providerId: String(target._id),
      preKeyId: preKey.keyId,
    });

    res.json({
      userId: String(target._id),
      registrationId: target.registrationId,
      deviceId: target.deviceId,
      identityKey: target.publicIdentityKey,
      signedPreKey: {
        keyId: target.signedPreKey.keyId,
        publicKey: target.signedPreKey.publicKey,
        signature: target.signedPreKey.signature,
      },
      oneTimePreKey: { keyId: preKey.keyId, publicKey: preKey.publicKey },
    });
  }),
);

export default router;