import jwt from 'jsonwebtoken';
import { config } from '../config.js';
import { User } from '../models/User.js';

const BEARER = /^Bearer\s+(.+)$/i;

export function signAccessToken(user) {
  return jwt.sign(
    { sub: String(user._id), phone: user.phone, reg: user.registrationId },
    config.JWT_SECRET,
    { expiresIn: config.ACCESS_TOKEN_TTL, issuer: 'securechat', audience: 'securechat-app' },
  );
}

export function verifyAccessToken(token) {
  return jwt.verify(token, config.JWT_SECRET, {
    issuer: 'securechat',
    audience: 'securechat-app',
  });
}

/** Extract a bearer token from the Authorization header, or null. */
export function extractToken(req) {
  const header = req.headers.authorization;
  if (!header) return null;
  const m = BEARER.exec(header.trim());
  return m ? m[1].trim() : null;
}

/**
 * Require a valid access token. Attaches `req.user` (a User document).
 */
export async function requireAuth(req, res, next) {
  try {
    const token = extractToken(req);
    if (!token) {
      return res.status(401).json({ error: 'unauthorized', message: 'Missing bearer token' });
    }

    let claims;
    try {
      claims = verifyAccessToken(token);
    } catch (err) {
      const message =
        err.name === 'TokenExpiredError' ? 'Access token expired' : 'Invalid access token';
      return res.status(401).json({ error: 'unauthorized', message });
    }

    const user = await User.findById(claims.sub);
    if (!user) {
      // Token is well-formed but the account is gone (deleted / wiped).
      return res.status(401).json({ error: 'unauthorized', message: 'Account no longer exists' });
    }

    req.user = user;
    req.token = token;
    next();
  } catch (err) {
    next(err);
  }
}

/**
 * Verify a Socket.io handshake. Returns claims, or throws.
 * Kept separate from the Express middleware because sockets do not have `res`.
 */
export async function authenticateHandshake(handshakeAuth) {
  const token =
    handshakeAuth?.token ||
    (typeof handshakeAuth === 'string' ? handshakeAuth : undefined) ||
    handshakeAuth?.Authorization;
  if (!token || typeof token !== 'string') {
    throw Object.assign(new Error('Missing socket token'), { data: { code: 'unauthorized' } });
  }
  const claims = verifyAccessToken(token.replace(/^Bearer\s+/i, ''));
  const user = await User.findById(claims.sub);
  if (!user) {
    throw Object.assign(new Error('Account no longer exists'), { data: { code: 'unauthorized' } });
  }
  return user;
}
