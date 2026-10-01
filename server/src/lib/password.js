import crypto from 'node:crypto';
import { config } from '../config.js';
import { HttpError } from '../middleware/error.js';

/**
 * Password hashing, validation, and the account-lockout policy.
 *
 * Passwords are never stored. Only a scrypt hash and its salt are persisted,
 * and neither is ever returned by an API, logged, or included in a token.
 *
 * scrypt is used rather than a fast hash because it is deliberately
 * memory-hard: it costs an attacker orders of magnitude more per guess than
 * SHA-256 would, which is what makes offline cracking of a leaked database
 * expensive. N = 2^15 with r = 8 needs roughly 32 MB and ~100 ms per
 * verification, which is affordable for a login and painful in bulk.
 */

const SCRYPT = { N: 2 ** 15, r: 8, p: 1, maxmem: 96 * 1024 * 1024 };
const KEY_BYTES = 32;
const SALT_BYTES = 16;

/** Minimum length. Long enough to resist guessing, short enough to type. */
export const MIN_PASSWORD_LENGTH = 8;
export const MAX_PASSWORD_LENGTH = 128;

/** Consecutive failed logins before the account is temporarily locked. */
export const MAX_FAILED_LOGINS = 8;

/** How long the lock lasts, in minutes. */
export const LOCK_MINUTES = 15;

/**
 * Reject passwords that are long but trivially guessable.
 *
 * Length alone is not enough: "11111111" passes any length rule and is among
 * the first things an attacker tries. This is a short list, not a claim to
 * exhaustiveness.
 */
const WEAK_PATTERNS = [
  /^(\d)\1+$/,
  /^(0123456789|1234567890|abcdefghij|qwertyuiop)/i,
  /^(pass|welcome|letmein|admin|secret|qwerty)/i,
  /^(.)\1+$/,
];

export function hashPassword(password) {
  const salt = crypto.randomBytes(SALT_BYTES);
  const hash = crypto.scryptSync(password, salt, KEY_BYTES, SCRYPT);
  return { salt: salt.toString('base64'), hash: hash.toString('base64') };
}

/**
 * Constant-time verification.
 *
 * The scrypt output length is fixed at KEY_BYTES and never taken from the
 * stored value. `hashB64` is read from the database, so using its decoded
 * length as the KDF output size would let a corrupted or tampered row decide
 * how much work the server does - a 64 KB "hash" turns a ~100 ms check into a
 * far heavier allocation-and-fill, repeated on every login attempt.
 *
 * timingSafeEqual also throws when the two buffers differ in length, so both
 * are checked against the known constants first and the comparison is only
 * reached when they are guaranteed to match.
 */
export function verifyPassword(password, saltB64, hashB64) {
  if (typeof saltB64 !== 'string' || typeof hashB64 !== 'string') return false;
  const salt = Buffer.from(saltB64, 'base64');
  const expected = Buffer.from(hashB64, 'base64');
  if (salt.length !== SALT_BYTES || expected.length !== KEY_BYTES) return false;

  const candidate = crypto.scryptSync(password, salt, KEY_BYTES, SCRYPT);
  return crypto.timingSafeEqual(candidate, expected);
}

/**
 * A hash of a value nobody knows, used to keep the "unknown account" login
 * path as slow as the "wrong password" one.
 *
 * Without this, a wrong password for a real account costs a scrypt run while a
 * non-existent account returns immediately, so response timing alone would
 * reveal which phone numbers have accounts.
 */
const DUMMY_SALT = crypto.randomBytes(SALT_BYTES).toString('base64');

/** Spend the same time a real verification would, for an unknown account. */
export function burnVerificationTime() {
  crypto.scryptSync('no-such-user', DUMMY_SALT, KEY_BYTES, SCRYPT);
}

/** Validate a candidate password, throwing a 400 with actionable wording. */
export function assertPasswordAcceptable(password) {
  const value = String(password ?? '');

  if (value.length < MIN_PASSWORD_LENGTH) {
    throw new HttpError(
      400,
      'weak_password',
      `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`,
    );
  }
  if (value.length > MAX_PASSWORD_LENGTH) {
    throw new HttpError(400, 'weak_password', 'Password is too long.');
  }
  if (WEAK_PATTERNS.some((re) => re.test(value))) {
    throw new HttpError(
      400,
      'weak_password',
      'That password is too easy to guess. Mix in letters and avoid runs of '
      + 'repeated or sequential characters.',
    );
  }
  if (/^\s+$/.test(value)) {
    throw new HttpError(400, 'weak_password', 'Password cannot be only spaces.');
  }
  return value;
}

/**
 * How long an account stays locked, or 0 if it is not locked.
 *
 * The lock lives on the user document rather than in memory so it survives a
 * restart; otherwise restarting the server would hand an attacker a fresh
 * budget of attempts.
 */
export function lockRemainingMs(user, now = Date.now()) {
  if (!user.lockedUntil) return 0;
  const remaining = user.lockedUntil.getTime() - now;
  return remaining > 0 ? remaining : 0;
}

/** Record a failed attempt, locking the account once the limit is reached. */
export function registerFailedLogin(user, now = new Date()) {
  user.failedLogins = (user.failedLogins || 0) + 1;
  if (user.failedLogins >= MAX_FAILED_LOGINS) {
    user.lockedUntil = new Date(now.getTime() + LOCK_MINUTES * 60 * 1000);
    // Reset the counter so the next window starts from zero once unlocked.
    user.failedLogins = 0;
  }
  return user;
}

export function clearFailedLogins(user) {
  user.failedLogins = 0;
  user.lockedUntil = undefined;
  return user;
}

/**
 * Normalise a phone number to E.164.
 *
 * Every sign-up, sign-in and lookup path funnels through this, so
 * "+91 98765 43210" and "+919876543210" collapse to one canonical string. That
 * is what makes "a number can only be registered once" actually hold: the
 * uniqueness check has to see the same value every time, or an attacker could
 * add a space to claim the same number twice.
 */
export function normalisePhone(rawPhone) {
  const trimmed = String(rawPhone ?? '').trim();
  const digits = trimmed.replace(/[\s\-().]/g, '');

  if (digits.startsWith('+')) {
    if (!/^\+[1-9]\d{6,14}$/.test(digits)) {
      throw new HttpError(
        400,
        'invalid_phone',
        'Enter a valid international number, for example +919876543210.',
      );
    }
    return digits;
  }

  // No country code given: treat it as international digits without the plus,
  // which is what most people type.
  if (/^[1-9]\d{6,14}$/.test(digits)) return `+${digits}`;

  throw new HttpError(
    400,
    'invalid_phone',
    'Enter a valid mobile number with its country code, for example '
    + '+919876543210.',
  );
}

/** A partially masked number, safe to put in a log. */
export function maskPhone(phone) {
  const s = String(phone ?? '');
  return s.length > 5 ? `${s.slice(0, 3)}***${s.slice(-2)}` : '***';
}
