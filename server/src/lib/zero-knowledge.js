/**
 * Zero-knowledge invariants for the server.
 *
 * These helpers are the mechanical guard rails behind the project's core rule:
 * "the server must never be able to see a message". They are deliberately
 * shared by the HTTP layer, the Mongoose schemas and the Socket.io layer so a
 * plaintext field cannot sneak in through any of the three.
 */

/** Field names that would imply the server holds readable message content. */
const FORBIDDEN_FIELDS = new Set([
  'plaintext',
  'plain',
  'text',
  'body',
  'message',
  'messagebody',
  'message_text',
  'msg',
  'content',
  'caption',
  'decrypted',
  'cleartext',
  'secret',
  'password',
  'privatekey',
  'identityprivatekey',
  'prekeyprivate',
  'groupkey',
  'sendermessagekey',
  'decryptionkey',
  'sessionkey',
  'messagedecryptionkey',
]);

/**
 * Fields that are permitted despite resembling forbidden names.
 *
 * `password` itself is rejected everywhere except the two auth routes, which
 * must receive a plaintext password in order to hash it. Those routes opt in
 * explicitly through the guard's `allowFields` option, so the exception is
 * visible at the call site rather than hidden in a global allowlist.
 *
 * `passwordHash` and `passwordSalt` are the stored scrypt output. A hash is
 * not plaintext and is not recoverable without the salt plus a large amount of
 * compute, so the User model's validation hook may carry them. Listing them
 * here documents that this was a decision, not an oversight: without this the
 * guard would reject them purely for resembling the word "password".
 */
const ALLOWED_FIELD_NAMES = new Set([
  'passwordhash',
  'passwordsalt',
  'passwordupdatedat',
  'failedlogins',
  'lockeduntil',
]);

/** Substrings that mark a key as suspicious even if not an exact match. */
const FORBIDDEN_PATTERNS = [/plain(text)?/i, /^_?(text|body|content|msg)$/i, /private_?key/i];

export class ZeroKnowledgeViolation extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'ZeroKnowledgeViolation';
    this.status = 400;
    this.code = 'PLAINTEXT_REJECTED';
    this.details = details;
  }
}

function isForbidden(key) {
  const k = String(key).toLowerCase().replace(/[\s-]/g, '');
  if (ALLOWED_FIELD_NAMES.has(k)) return false;
  if (FORBIDDEN_FIELDS.has(k)) return true;
  return FORBIDDEN_PATTERNS.some((re) => re.test(k));
}

/**
 * Recursively scan an object for plaintext-bearing field names.
 *
 * @param {Set<string>} allowFields lower-cased names permitted in this payload,
 *   used by the auth routes for the one field a login genuinely has to send.
 * @throws {ZeroKnowledgeViolation} on the first hit, naming the full path.
 */
export function assertNoPlaintext(
  value,
  path = '$',
  seen = new WeakSet(),
  allowFields = new Set(),
) {
  if (value === null || typeof value !== 'object') return value;
  if (seen.has(value)) return value; // tolerate cycles
  seen.add(value);

  if (Array.isArray(value)) {
    value.forEach((item, i) =>
      assertNoPlaintext(item, `${path}[${i}]`, seen, allowFields),
    );
    return value;
  }

  for (const [key, val] of Object.entries(value)) {
    const normalised = String(key).toLowerCase().replace(/[\s-]/g, '');
    if (isForbidden(key) && !allowFields.has(normalised)) {
      throw new ZeroKnowledgeViolation(
        `Refusing to accept field "${key}" at ${path}: the server is zero-knowledge and must never receive message plaintext.`,
        { path: `${path}.${key}`, field: key },
      );
    }
    assertNoPlaintext(val, `${path}.${key}`, seen, allowFields);
  }
  return value;
}

/** Non-throwing variant, for the HTTP middleware. */
export function findPlaintext(value, allowFields) {
  try {
    assertNoPlaintext(value, '$', new WeakSet(), allowFields);
    return null;
  } catch (err) {
    if (err instanceof ZeroKnowledgeViolation) return err;
    throw err;
  }
}

/**
 * Assert that the server never receives private key material, or a plaintext
 * password on a route that has not opted in.
 *
 * A device may only ever publish public halves. `allowed` carries the same
 * lower-cased exemptions the request-level guard uses, so a rejected password
 * is not treated as a leaked secret.
 */
export function assertPublicOnly(value, path = '$', seen = new WeakSet(), allowed = new Set()) {
  if (value === null || typeof value !== 'object') return value;
  if (seen.has(value)) return value;
  seen.add(value);

  if (Array.isArray(value)) {
    value.forEach((item, i) => assertPublicOnly(item, `${path}[${i}]`, seen, allowed));
    return value;
  }

  for (const [key, val] of Object.entries(value)) {
    const k = String(key).toLowerCase().replace(/[\s-]/g, '');
    const exempt = allowed.has(k);
    if (!exempt) {
      if (
        k === 'privatekey' ||
        k.endsWith('privatekey') ||
        k === 'private' ||
        k === 'secretkey'
      ) {
        throw new ZeroKnowledgeViolation(
          `Refusing to accept private key material at ${path}.${key}. Private keys must stay on the device.`,
          { path: `${path}.${key}`, field: key },
        );
      }
    }
    assertPublicOnly(val, `${path}.${key}`, seen, allowed);
  }
  return value;
}
