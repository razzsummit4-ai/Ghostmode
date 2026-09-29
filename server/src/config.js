/**
 * Central, validated configuration.
 *
 * The server is zero-knowledge: nothing in here may ever hold, derive or
 * transmit user key material. Only transport credentials (JWT signing key)
 * and third-party service credentials live on this side.
 */
import 'dotenv/config';
import { z } from 'zod';

const bool = (def) =>
  z
    .string()
    .optional()
    .transform((v) => (v === undefined || v === '' ? def : /^(1|true|yes|on)$/i.test(v)));

const csv = (def) =>
  z
    .string()
    .optional()
    .transform((v) =>
      (v === undefined || v === '' ? def : v.split(',').map((s) => s.trim()).filter(Boolean)),
    );

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().positive().default(4000),
  PUBLIC_URL: z.string().url().default('http://localhost:4000'),

  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters'),
  ACCESS_TOKEN_TTL: z.string().default('30d'),

  MONGODB_URI: z.string().min(1).default('mongodb://127.0.0.1:27017/securechat'),

  // --- Brute-force protection ------------------------------------------------
  // Applied to the password endpoints in lib/password.js. A higher
  // AUTH_RATE_LIMIT_MAX is the first line of defence; the per-account lockout is
  // the second, because an IP-based limit alone does not stop a distributed
  // attack on one account.
  MAX_FAILED_LOGINS: z.coerce.number().int().positive().default(8),
  LOCK_MINUTES: z.coerce.number().int().positive().default(15),

  STORAGE_DRIVER: z.enum(['local', 's3']).default('local'),
  MEDIA_DIR: z.string().default('./var/media'),
  MEDIA_MAX_BYTES: z.coerce.number().int().positive().default(25 * 1024 * 1024),
  S3_BUCKET: z.string().optional().default(''),
  S3_REGION: z.string().default('us-east-1'),
  S3_ENDPOINT: z.string().optional().default(''),
  S3_FORCE_PATH_STYLE: bool(false),
  AWS_ACCESS_KEY_ID: z.string().optional().default(''),
  AWS_SECRET_ACCESS_KEY: z.string().optional().default(''),
  PRESIGN_TTL_SECONDS: z.coerce.number().int().positive().default(900),

  // --- Embedded database ---------------------------------------------------
  // When AUTO_DB=embedded, a local mongod is started for this process so the
  // server needs no separate database installation. This is what makes a
  // single-command install possible for a self-hoster; a real deployment
  // should set MONGODB_URI to a managed instance instead.
  AUTO_DB: z.enum(['mongo', 'embedded']).default('mongo'),
  EMBEDDED_DB_DIR: z.string().default('./var/db'),
  EMBEDDED_DB_PORT: z.coerce.number().int().positive().default(27018),

  // How long to wait for the embedded mongod to report it is accepting
  // connections. mongodb-memory-server's own default is 10 s, which a cold
  // start, a spinning disk, antivirus scanning, or a project folder living on a
  // synced drive (OneDrive/Dropbox/Google Drive) routinely exceeds. When that
  // clock runs out the server refuses to boot at all, which looks to the user
  // like "login does not work" rather than "the database was slow".
  EMBEDDED_DB_LAUNCH_TIMEOUT_MS: z.coerce.number().int().positive().default(120_000),

  // --- Port binding ----------------------------------------------------------
  // If another process already holds PORT, move to the next free one instead of
  // dying. See index.js: a stale server from a different project on the same
  // port is the most common reason a correctly built app cannot sign in.
  PORT_AUTO_FALLBACK: bool(true),

  RATE_LIMIT_WINDOW_MS: z.coerce.number().int().positive().default(60_000),
  RATE_LIMIT_MAX: z.coerce.number().int().positive().default(600),
  AUTH_RATE_LIMIT_MAX: z.coerce.number().int().positive().default(10),
  // "Is this number already registered?" is a typing aid shown while the user
  // fills in the form, not a credential check. Counting it against the tight
  // password budget is what turns a few edits of a phone number into
  // "Too many authentication attempts" before the user has even submitted.
  AUTH_PROBE_RATE_LIMIT_MAX: z.coerce.number().int().positive().default(60),
  MESSAGE_RATE_LIMIT_MAX: z.coerce.number().int().positive().default(120),

  CORS_ORIGINS: csv(['*']),

  // --- LAN discovery ---------------------------------------------------------
  // Lets a phone on the same Wi-Fi find this server by UDP broadcast instead of
  // the user having to read an IP address off a terminal and type it in. The
  // announcement carries public addresses only - no keys, no user data.
  DISCOVERY_ENABLED: bool(true),
  DISCOVERY_PORT: z.coerce.number().int().positive().max(65535).default(41234),
  DISCOVERY_NAME: z.string().max(48).default('SecureChat server'),
});

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  const detail = parsed.error.issues.map((i) => `  - ${i.path.join('.')}: ${i.message}`).join('\n');
  // Fail fast and loudly rather than starting with a weak/partial config.
  throw new Error(`Invalid server configuration:\n${detail}\n\nCopy server/.env.example to server/.env`);
}

const env = parsed.data;

if (env.NODE_ENV === 'production') {
  if (env.JWT_SECRET.startsWith('dev-only')) {
    throw new Error('Refusing to boot: JWT_SECRET still holds the development placeholder.');
  }
  if (env.STORAGE_DRIVER === 'local') {
    console.warn('[config] WARNING: STORAGE_DRIVER=local in production. Use an S3-compatible bucket.');
  }
}

export const config = {
  ...env,
  isProd: env.NODE_ENV === 'production',
  isTest: env.NODE_ENV === 'test',
};
