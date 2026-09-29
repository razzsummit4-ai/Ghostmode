import { logger } from '../logger.js';
import { ZeroKnowledgeViolation } from '../lib/zero-knowledge.js';

export class HttpError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.status = status;
    this.code = code;
    if (details) this.details = details;
  }
}

export const notFound = (req, res) =>
  res.status(404).json({ error: 'not_found', message: `No route for ${req.method} ${req.path}` });

/** Central error serialiser. Never leaks internals in production. */
// eslint-disable-next-line no-unused-vars -- Express identifies error handlers by arity.
export function errorHandler(err, req, res, next) {
  if (err instanceof ZeroKnowledgeViolation) {
    return res
      .status(400)
      .json({ error: 'zero_knowledge_violation', code: err.code, message: err.message });
  }

  if (err instanceof HttpError) {
    return res.status(err.status).json({
      // `code` is the stable machine-readable identifier; `error` mirrors it
      // for the earlier routes and the existing client error handling, so both
      // conventions work rather than forcing every caller to know which one a
      // given endpoint used.
      error: err.code,
      code: err.code,
      message: err.message,
      ...(err.details ? { details: err.details } : {}),
    });
  }

  if (err?.name === 'ZodError') {
    return res.status(400).json({
      error: 'validation_failed',
      message: 'Request payload failed validation.',
      details: err.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
    });
  }

  if (err?.name === 'ValidationError' || err?.name === 'StrictModeError') {
    // Raised by the Mongoose schema guards in models/*.js.
    return res.status(400).json({
      error: 'schema_rejected',
      message: err.message,
    });
  }

  if (err?.code === 11000) {
    return res.status(409).json({ error: 'conflict', message: 'Resource already exists.' });
  }

  const status = err.status || err.statusCode || 500;
  logger.error('unhandled', {
    method: req.method,
    path: req.originalUrl?.split('?')[0],
    userId: req.user?.id,
    err: err.message,
    name: err.name,
    stack: process.env.NODE_ENV !== 'production' ? err.stack?.split('\n').slice(0, 6).join(' | ') : undefined,
  });

  res.status(status).json({
    error: 'internal_error',
    message: 'Something went wrong on our side.',
  });
}

/** Wrap an async route so rejections reach the error handler. */
export const asyncRoute = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
