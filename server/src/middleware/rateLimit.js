import rateLimit from 'express-rate-limit';
import { config } from '../config.js';

const keyByUserOrIp = (req) => (req.user ? `u:${req.user._id}` : `ip:${req.ip}`);

function make({ windowMs, max, code, message }) {
  return rateLimit({
    windowMs,
    max,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    keyGenerator: keyByUserOrIp,
    // Authenticated routes are safe to count per user; anonymous ones fall back
    // to the IP that express-rate-limit's default handler already resolved.
    handler: (req, res) => {
      res.status(429).json({ error: code, message });
    },
  });
}

/** Broad limiter applied to the whole API surface. */
export const globalLimiter = make({
  windowMs: config.RATE_LIMIT_WINDOW_MS,
  max: config.RATE_LIMIT_MAX,
  code: 'too_many_requests',
  message: 'Too many requests. Slow down.',
});

/** Tight limiter for the password endpoints (brute-force protection). */
export const authLimiter = make({
  windowMs: config.RATE_LIMIT_WINDOW_MS,
  max: config.AUTH_RATE_LIMIT_MAX,
  code: 'auth_rate_limited',
  message: 'Too many authentication attempts. Try again later.',
});

/**
 * Limiter for the "has this number been registered?" lookup.
 *
 * That lookup is a typing aid the form fires while the user edits the number,
 * not a credential check, so it gets its own generous bucket. Sharing the
 * password budget with it is what produces "Too many authentication attempts"
 * on a device where the user has typed a wrong digit and tried again twice —
 * they never even reached the submit button.
 */
export const probeLimiter = make({
  windowMs: config.RATE_LIMIT_WINDOW_MS,
  max: config.AUTH_PROBE_RATE_LIMIT_MAX,
  code: 'auth_probe_rate_limited',
  message: 'That was a lot of lookups. Give it a minute.',
});

/** Limiter for message submission, to bound storage abuse. */
export const messageLimiter = make({
  windowMs: config.RATE_LIMIT_WINDOW_MS,
  max: config.MESSAGE_RATE_LIMIT_MAX,
  code: 'message_rate_limited',
  message: 'Sending messages too quickly.',
});

/** Limiter for media upload, which is expensive. */
export const mediaLimiter = make({
  windowMs: config.RATE_LIMIT_WINDOW_MS,
  max: 30,
  code: 'media_rate_limited',
  message: 'Too many uploads. Try again shortly.',
});
