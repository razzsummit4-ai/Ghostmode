import { findPlaintext, assertPublicOnly, ZeroKnowledgeViolation } from '../lib/zero-knowledge.js';
import { logger } from '../logger.js';

/**
 * The zero-knowledge firewall.
 *
 * Every mutating request passes through here before it reaches a route handler
 * or a Mongoose document. If the client has accidentally (or maliciously)
 * included a plaintext-bearing field, the request is rejected with 400 and
 * nothing is persisted.
 *
 * @param allowPrivateKeys permit key-shaped names (used by no current route).
 * @param allowFields lower-cased field names this one route may legitimately
 *   carry. Only `/register` and `/login` pass `['password']`, because hashing a
 *   password requires receiving it. The exception is written at the call site
 *   so it is reviewable rather than buried in the guard.
 */
export function zeroKnowledgeGuard({ allowPrivateKeys = false, allowFields = [] } = {}) {
  const allowed = new Set(allowFields.map((f) => String(f).toLowerCase()));

  return function guard(req, res, next) {
    const sources = [];

    // express.json() has already parsed the body at this point.
    if (req.body && typeof req.body === 'object') sources.push(['body', req.body]);

    // Key uploads must never carry a private half.
    if (!allowPrivateKeys && req.params?.userId) {
      sources.push(['params', { userId: req.params.userId }]);
    }

    for (const [origin, payload] of sources) {
      try {
        if (!allowPrivateKeys) assertPublicOnly(payload, '$', new WeakSet(), allowed);
        const violation = findPlaintext(payload, allowed);
        if (violation) {
          // Deliberately logs only the field name. A rejected password must
          // never reach the log, so the value is not included anywhere here.
          logger.warn('zk.rejected', {
            userId: req.user?.id,
            method: req.method,
            path: req.originalUrl.split('?')[0],
            field: violation.details?.field,
          });
          return res.status(400).json({
            error: 'zero_knowledge_violation',
            code: violation.code,
            message: violation.message,
          });
        }
      } catch (err) {
        if (err instanceof ZeroKnowledgeViolation) {
          logger.warn('zk.rejected', { userId: req.user?.id, method: req.method });
          return res.status(400).json({
            error: 'zero_knowledge_violation',
            code: err.code,
            message: err.message,
          });
        }
        return next(err);
      }
    }

    next();
  };
}

/**
 * Wrapper for route handlers: converts a thrown ZeroKnowledgeViolation into a
 * clean 400 instead of a 500.
 */
export function zeroKnowledgeHandler(fn) {
  return async function wrapped(req, res, next) {
    try {
      await fn(req, res, next);
    } catch (err) {
      if (err instanceof ZeroKnowledgeViolation) {
        return res.status(400).json({
          error: 'zero_knowledge_violation',
          code: err.code,
          message: err.message,
        });
      }
      next(err);
    }
  };
}
