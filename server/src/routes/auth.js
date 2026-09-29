import { Router } from 'express';
import { z } from 'zod';
import crypto from 'node:crypto';
import { config } from '../config.js';
import { User } from '../models/User.js';
import {
  assertPasswordAcceptable,
  burnVerificationTime,
  clearFailedLogins,
  hashPassword,
  lockRemainingMs,
  maskPhone,
  normalisePhone,
  registerFailedLogin,
  verifyPassword,
  MAX_PASSWORD_LENGTH,
  MIN_PASSWORD_LENGTH,
} from '../lib/password.js';
import { signAccessToken, requireAuth } from '../middleware/auth.js';
import { authLimiter, probeLimiter } from '../middleware/rateLimit.js';
import { asyncRoute, HttpError } from '../middleware/error.js';
import { zeroKnowledgeGuard } from '../middleware/zeroKnowledge.js';
import { logger } from '../logger.js';

const router = Router();

/**
 * The public key bundle a client generates on-device and may attach to
 * sign-up or sign-in so it can send immediately.
 *
 * Public halves only. The private keys never leave the device, and the
 * zero-knowledge guard enforces that on every other route.
 */
const keyBundleSchema = z.object({
  publicIdentityKey: z.string().min(1).max(128).optional(),
  signedPreKey: z
    .object({
      keyId: z.number().int().nonnegative(),
      publicKey: z.string().min(1).max(128),
      signature: z.string().min(1).max(256),
    })
    .optional(),
  oneTimePreKeys: z
    .array(
      z.object({
        keyId: z.number().int().nonnegative(),
        publicKey: z.string().min(1).max(128),
      }),
    )
    .max(200)
    .optional(),
  deviceName: z.string().max(80).optional(),
  deviceId: z.string().max(64).optional(),
  displayName: z.string().max(64).optional(),
});

const registerSchema = keyBundleSchema.extend({
  phone: z.string().min(6).max(20),
  password: z.string().min(1).max(MAX_PASSWORD_LENGTH),
});

const loginSchema = keyBundleSchema.extend({
  phone: z.string().min(6).max(20),
  password: z.string().min(1).max(MAX_PASSWORD_LENGTH),
});

/**
 * Attach a key bundle to a user, returning whether it changed anything.
 *
 * A new identity key implies a new registration id, per the Signal spec. This
 * is also how a user signing in on a fresh device publishes the keys for that
 * new device, since each install generates its own identity.
 */
function applyKeyBundle(user, body) {
  const hasBundle =
    Boolean(body.publicIdentityKey) &&
    Boolean(body.signedPreKey?.publicKey) &&
    Boolean(body.signedPreKey?.signature) &&
    Array.isArray(body.oneTimePreKeys) &&
    body.oneTimePreKeys.length > 0;

  if (!hasBundle) return false;
  if (user.publicIdentityKey === body.publicIdentityKey) return false;

  user.publicIdentityKey = body.publicIdentityKey;
  user.signedPreKey = {
    keyId: body.signedPreKey.keyId,
    publicKey: body.signedPreKey.publicKey,
    signature: body.signedPreKey.signature,
    createdAt: new Date(),
  };
  user.oneTimePreKeys = body.oneTimePreKeys.map((k) => ({
    ...k,
    createdAt: new Date(),
  }));
  user.registrationId = crypto.randomBytes(4).readUInt32BE(0) & 0x3fffffff;
  return true;
}

function touchDevice(user, body) {
  user.lastSeenAt = new Date();
  if (body.displayName) user.displayName = body.displayName;
  if (body.deviceName) user.deviceName = body.deviceName;
  if (body.deviceId) user.deviceId = body.deviceId;
}

/**
 * POST /api/auth/register
 *
 * Body: { phone, password, ...optional first-login key bundle }
 *
 * A phone number can be registered exactly once, ever. A repeat attempt is
 * refused with 409 and the existing account is left completely untouched, so
 * this endpoint can never be used to take over a number already in use.
 * Signing in to an existing account is POST /api/auth/login.
 *
 * On the zero-knowledge exception: this is one of two places the server
 * accepts a plaintext password, and it exists because hashing requires
 * receiving it. The value is never stored, never logged, and never returned.
 */
router.post(
  '/register',
  authLimiter,
  zeroKnowledgeGuard({ allowFields: ['password'] }),
  asyncRoute(async (req, res) => {
    const body = registerSchema.parse(req.body);
    const phone = normalisePhone(body.phone);
    assertPasswordAcceptable(body.password);

    // Reject a taken number before doing any hashing work. The unique index on
    // `phone` is the authoritative guard against a race between two concurrent
    // registrations; this check just produces a clean 409 in the common case.
    const existing = await User.findOne({ phone }).select('_id');
    if (existing) {
      logger.warn('auth.register_conflict', { phoneHint: maskPhone(phone) });
      throw new HttpError(
        409,
        'number_already_registered',
        'An account already exists for this number. Sign in instead, or reset '
        + 'your password if you have forgotten it.',
      );
    }

    const { salt, hash } = hashPassword(body.password);
    const user = new User({
      phone,
      passwordHash: hash,
      passwordSalt: salt,
      passwordUpdatedAt: new Date(),
      displayName: body.displayName || `User ${phone.slice(-4)}`,
      deviceName: body.deviceName || 'Unknown device',
      deviceId: body.deviceId || crypto.randomBytes(16).toString('hex'),
      // Left null until the key bundle below is applied. The client cannot send
      // or receive anything until this is populated.
      publicIdentityKey: null,
      registrationId: crypto.randomBytes(4).readUInt32BE(0) & 0x3fffffff,
      lastSeenAt: new Date(),
    });

    const keysUploaded = applyKeyBundle(user, body);

    try {
      await user.save();
    } catch (err) {
      // Losing the race against a concurrent registration is the expected path
      // here, and must produce the same 409 rather than a 500.
      if (err?.code === 11000) {
        throw new HttpError(
          409,
          'number_already_registered',
          'An account already exists for this number. Sign in instead.',
        );
      }
      throw err;
    }

    const token = signAccessToken(user);
    // The phone is masked and neither the password nor its hash is logged, so
    // the log cannot be used to enumerate accounts.
    logger.info('auth.registered', {
      userId: String(user._id),
      phoneHint: maskPhone(phone),
      keysUploaded,
    });

    res.status(201).json({
      token,
      expiresIn: config.ACCESS_TOKEN_TTL,
      isNewUser: true,
      keysUploaded,
      user: publicUser(user),
      needsKeyUpload: !keysUploaded && user.publicIdentityKey === null,
    });
  }),
);

/**
 * POST /api/auth/login
 *
 * Body: { phone, password, ...optional key bundle for a new device }
 *
 * A wrong password and an unknown account are reported identically, and an
 * unknown account still pays the cost of a scrypt verification, so neither the
 * message nor the response time reveals which numbers are registered.
 */
router.post(
  '/login',
  authLimiter,
  zeroKnowledgeGuard({ allowFields: ['password'] }),
  asyncRoute(async (req, res) => {
    const body = loginSchema.parse(req.body);
    const phone = normalisePhone(body.phone);

    // The credential fields are `select: false`, so they must be requested
    // explicitly. `lockedUntil` too, for the lockout check.
    const user = await User.findOne({ phone })
      .select('+passwordHash +passwordSalt +failedLogins +lockedUntil');

    if (!user) {
      // Burn equivalent time so this path is indistinguishable from a wrong
      // password, which prevents enumerating registered numbers by timing.
      burnVerificationTime();
      logger.warn('auth.login_failed', {
        phoneHint: maskPhone(phone),
        reason: 'no_account',
      });
      throw new HttpError(401, 'invalid_credentials', 'Number or password is incorrect.');
    }

    const lockedFor = lockRemainingMs(user);
    if (lockedFor > 0) {
      const minutes = Math.ceil(lockedFor / 60000);
      throw new HttpError(
        429,
        'account_locked',
        `Too many failed attempts. Try again in ${minutes} minute(s).`,
      );
    }

    if (!verifyPassword(body.password, user.passwordSalt, user.passwordHash)) {
      registerFailedLogin(user);
      await user.save();
      logger.warn('auth.login_failed', { userId: String(user._id), reason: 'bad_password' });
      throw new HttpError(401, 'invalid_credentials', 'Number or password is incorrect.');
    }

    clearFailedLogins(user);
    touchDevice(user, body);
    const keysUploaded = applyKeyBundle(user, body);
    await user.save();

    const token = signAccessToken(user);
    logger.info('auth.login', {
      userId: String(user._id),
      phoneHint: maskPhone(phone),
      keysUploaded,
    });

    res.json({
      token,
      expiresIn: config.ACCESS_TOKEN_TTL,
      isNewUser: false,
      keysUploaded,
      user: publicUser(user),
      // A device that has never published keys must do so before it can chat.
      needsKeyUpload: user.publicIdentityKey === null,
    });
  }),
);

/** Whether an account exists for a number, revealing nothing else. */
router.get(
  '/check/:phone',
  probeLimiter,
  asyncRoute(async (req, res) => {
    const phone = normalisePhone(req.params.phone);
    const user = await User.findOne({ phone }).select('_id');
    res.json({ phone, registered: Boolean(user) });
  }),
);

/** Password rules, so the client can validate before submitting. */
router.get(
  '/policy',
  asyncRoute(async (req, res) => {
    res.json({
      minLength: MIN_PASSWORD_LENGTH,
      maxLength: MAX_PASSWORD_LENGTH,
      // A human-readable hint, never enforced against the stored hash.
      note: 'Mix letters, numbers or symbols. Avoid repeated digits and common words.',
    });
  }),
);

/** GET /api/auth/me - current identity + pre-key health. */
router.get(
  '/me',
  requireAuth,
  asyncRoute(async (req, res) => {
    const user = req.user;
    const remaining = user.oneTimePreKeys.length;
    res.json({
      user: publicUser(user),
      // The client tops this pool up when it runs low.
      preKeyHealth: { remaining, low: remaining < 20, critical: remaining === 0 },
    });
  }),
);

/** PATCH /api/auth/me - non-key profile fields only. Credentials are separate. */
router.patch(
  '/me',
  requireAuth,
  zeroKnowledgeGuard(),
  asyncRoute(async (req, res) => {
    const patch = z
      .object({
        displayName: z.string().max(64).optional(),
        avatarColor: z.number().int().min(0).max(11).optional(),
      })
      .parse(req.body);
    Object.assign(req.user, patch);
    await req.user.save();
    res.json({ user: publicUser(req.user) });
  }),
);

/**
 * POST /api/auth/change-password
 *
 * Requires the current password, so a stolen token alone cannot lock the real
 * owner out. The salt is regenerated, so the previous hash stops being valid
 * immediately rather than lingering as a second accepted secret.
 */
router.post(
  '/change-password',
  requireAuth,
  authLimiter,
  zeroKnowledgeGuard({ allowFields: ['password', 'currentPassword'] }),
  asyncRoute(async (req, res) => {
    const body = z
      .object({
        currentPassword: z.string().min(1).max(MAX_PASSWORD_LENGTH),
        newPassword: z.string().min(1).max(MAX_PASSWORD_LENGTH),
      })
      .parse(req.body);

    const user = await User.findById(req.user._id)
      .select('+passwordHash +passwordSalt +failedLogins +lockedUntil');

    if (!verifyPassword(body.currentPassword, user.passwordSalt, user.passwordHash)) {
      registerFailedLogin(user);
      await user.save();
      throw new HttpError(401, 'invalid_credentials', 'Current password is incorrect.');
    }
    assertPasswordAcceptable(body.newPassword);

    const { salt, hash } = hashPassword(body.newPassword);
    user.passwordSalt = salt;
    user.passwordHash = hash;
    user.passwordUpdatedAt = new Date();
    clearFailedLogins(user);
    await user.save();

    logger.info('auth.password_changed', { userId: String(user._id) });
    res.json({ ok: true });
  }),
);

export default router;

/** Shape sent to clients. Never includes anything secret. */
export function publicUser(user) {
  return {
    id: String(user._id),
    phone: user.phone,
    displayName: user.displayName,
    publicIdentityKey: user.publicIdentityKey,
    registrationId: user.registrationId,
    deviceName: user.deviceName,
    deviceId: user.deviceId,
    avatarColor: user.avatarColor,
    lastSeenAt: user.lastSeenAt,
    preKeyCount: user.oneTimePreKeys.length,
    createdAt: user.createdAt,
  };
}
