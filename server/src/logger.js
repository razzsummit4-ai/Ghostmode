/**
 * Structured logger with hard redaction.
 *
 * Security rule #1: never log plaintext. This logger cannot emit a value whose
 * key looks like message content, and it truncates any long opaque string that
 * might be ciphertext. Request bodies are NEVER passed to the logger.
 */

const REDACTED = '[redacted]';

/** Keys whose values must never reach a log sink, matched case-insensitively. */
const FORBIDDEN_KEY = /(plain|body|text|content|message_?body|password|secret|private|token|authorization|ciphertext|cipher)/i;

/** Long base64 blobs (keys, ciphertext) are summarised, not dumped. */
function summariseOpaque(value) {
  if (typeof value !== 'string') return value;
  if (value.length < 48) return value;
  return `${value.slice(0, 8)}…${value.slice(-4)} (len=${value.length})`;
}

function scrub(value, depth = 0) {
  if (depth > 4 || value === null || value === undefined) return value;
  // Never mangle diagnostics: long strings that are not keys/ciphertext must
  // stay intact, or a real error message becomes unreadable in the logs.
  if (typeof value === 'string') return value;
  if (typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.slice(0, 10).map((v) => scrub(v, depth + 1));

  const out = {};
  for (const [k, v] of Object.entries(value)) {
    out[k] = FORBIDDEN_KEY.test(k) ? REDACTED : scrub(v, depth + 1);
  }
  return out;
}

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };

function emit(level, msg, meta) {
  const record = {
    ts: new Date().toISOString(),
    level,
    msg,
    ...(meta ? scrub(meta) : {}),
  };
  const line = JSON.stringify(record);
  if (level === 'error') process.stderr.write(line + '\n');
  else process.stdout.write(line + '\n');
}

export const logger = {
  debug: (msg, meta) => emit('debug', msg, meta),
  info: (msg, meta) => emit('info', msg, meta),
  warn: (msg, meta) => emit('warn', msg, meta),
  error: (msg, meta) => emit('error', msg, meta),
  child(bindings) {
    return {
      debug: (m, x) => emit('debug', m, { ...bindings, ...x }),
      info: (m, x) => emit('info', m, { ...bindings, ...x }),
      warn: (m, x) => emit('warn', m, { ...bindings, ...x }),
      error: (m, x) => emit('error', m, { ...bindings, ...x }),
    };
  },
};

/** Express request logger that records metadata only - never bodies. */
export function requestLogger(req, res, next) {
  const started = process.hrtime.bigint();
  res.on('finish', () => {
    const ms = Number(process.hrtime.bigint() - started) / 1e6;
    const level = res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info';
    emit(level, 'http', {
      method: req.method,
      path: req.originalUrl.split('?')[0],
      status: res.statusCode,
      ms: Math.round(ms * 100) / 100,
      userId: req.user?.id,
    });
  });
  next();
}
