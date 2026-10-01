import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { config } from '../config.js';
import { HttpError } from '../middleware/error.js';
import { logger } from '../logger.js';

/**
 * Encrypted-blob object storage.
 *
 * The client encrypts media with a random AES-256-GCM key BEFORE upload, so
 * this store only ever holds opaque ciphertext. Two interchangeable drivers:
 *
 *   local - writes to ./var/media (zero-config, great for development)
 *   s3    - AWS S3 or any S3-compatible endpoint, using short-lived presigned
 *           PUT/GET URLs so file bytes never transit this Node process.
 *
 * The object key is an opaque random id, never a filename supplied by a client.
 */

const HEX = '0123456789abcdef';

function randomId(bytes = 15) {
  const buf = crypto.randomBytes(bytes);
  let out = '';
  for (const b of buf) out += HEX[b >> 4] + HEX[b & 15];
  return out;
}

/** Sharded key: ab/cd/<30 hex chars>. Keeps directory listings manageable. */
function buildKey() {
  const id = randomId(15);
  return `${id.slice(0, 2)}/${id.slice(2, 4)}/${id}`;
}

const CONTENT_TYPES = new Set([
  'application/octet-stream',
  'image/jpeg',
  'image/png',
  'image/webp',
  'image/gif',
  'video/mp4',
  'video/quicktime',
  'video/webm',
  'audio/mpeg',
  'audio/mp4',
  'application/pdf',
]);

function assertContentType(value) {
  const ct = String(value || 'application/octet-stream').split(';')[0].trim().toLowerCase();
  if (!CONTENT_TYPES.has(ct)) {
    throw new HttpError(400, 'unsupported_media_type', `Content-Type "${ct}" is not allowed.`);
  }
  return ct;
}

// ---------------------------- local driver ----------------------------------

/**
 * The origin clients should use to reach this server.
 *
 * `config.PUBLIC_URL` is the configured answer, but it is unset on most
 * deployments - including Render, where the default is `http://localhost:4000`.
 * A presigned upload URL built from that is unreachable from a phone, so every
 * attachment silently fails even though the server is healthy.
 *
 * So when the configured value still points at a loopback address, the request's
 * own scheme and host are used instead: behind a proxy `trust proxy` makes
 * `protocol` correct, and the Host header is exactly the address the client
 * already reached us on. Anything explicitly configured and non-loopback is
 * honoured unchanged, which keeps LAN and on-premise setups working.
 */
export function publicOrigin(req) {
  const configured = String(config.PUBLIC_URL || '');
  const isLoopback =
    /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?(\/|$)/i.test(configured) ||
    configured === '';

  if (!isLoopback) return configured.replace(/\/+$/, '');
  if (!req) return configured.replace(/\/+$/, '') || 'http://localhost:4000';

  const host = req.headers?.host;
  if (!host) return configured.replace(/\/+$/, '') || 'http://localhost:4000';
  return `${req.protocol}://${host}`;
}

function localDriver() {
  const root = path.resolve(config.MEDIA_DIR);
  const safePath = (objectKey) => {
    const dest = path.resolve(root, objectKey);
    if (!dest.startsWith(root + path.sep)) throw new HttpError(400, 'bad_key', 'Invalid object key.');
    return dest;
  };

  return {
    name: 'local',
    async createUploadUrl({ objectKey, contentType }, req) {
      await fs.mkdir(path.dirname(safePath(objectKey)), { recursive: true });
      return {
        uploadUrl: `${publicOrigin(req)}/api/media/blob/${encodeURIComponent(objectKey)}`,
        method: 'PUT',
        headers: { 'content-type': contentType },
        expiresInSeconds: config.PRESIGN_TTL_SECONDS,
      };
    },
    async createDownloadUrl({ objectKey }, req) {
      return {
        downloadUrl: `${publicOrigin(req)}/api/media/blob/${encodeURIComponent(objectKey)}`,
        expiresInSeconds: config.PRESIGN_TTL_SECONDS,
      };
    },
    async put({ objectKey, buffer, contentType }) {
      const dest = safePath(objectKey);
      await fs.mkdir(path.dirname(dest), { recursive: true });
      await fs.writeFile(dest, buffer, { mode: 0o600 });
      logger.info('media.stored', { driver: 'local', objectKey, bytes: buffer.length, contentType });
      return objectKey;
    },
    async get({ objectKey }) {
      return fs.readFile(safePath(objectKey));
    },
    async remove({ objectKey }) {
      await fs.rm(safePath(objectKey), { force: true });
    },
  };
}

// ----------------------------- s3 driver -----------------------------------
function s3Driver() {
  let clientPromise = null;
  const getClient = async () => {
    if (!clientPromise) {
      const { S3Client } = await import('@aws-sdk/client-s3');
      clientPromise = new S3Client({
        region: config.S3_REGION,
        ...(config.S3_ENDPOINT ? { endpoint: config.S3_ENDPOINT } : {}),
        forcePathStyle: config.S3_FORCE_PATH_STYLE,
        ...(config.AWS_ACCESS_KEY_ID
          ? {
              credentials: {
                accessKeyId: config.AWS_ACCESS_KEY_ID,
                secretAccessKey: config.AWS_SECRET_ACCESS_KEY,
              },
            }
          : {}),
      });
    }
    return clientPromise;
  };
  const prefix = 'blobs/';

  return {
    name: 's3',
    async createUploadUrl({ objectKey, contentType }) {
      const [{ PutObjectCommand }, { getSignedUrl }] = await Promise.all([
        import('@aws-sdk/client-s3'),
        import('@aws-sdk/s3-request-presigner'),
      ]);
      const command = new PutObjectCommand({
        Bucket: config.S3_BUCKET,
        Key: prefix + objectKey,
        ContentType: contentType,
      });
      return {
        uploadUrl: await getSignedUrl(await getClient(), command, {
          expiresIn: config.PRESIGN_TTL_SECONDS,
        }),
        method: 'PUT',
        headers: { 'content-type': contentType },
        expiresInSeconds: config.PRESIGN_TTL_SECONDS,
      };
    },
    async createDownloadUrl({ objectKey }) {
      const [{ GetObjectCommand }, { getSignedUrl }] = await Promise.all([
        import('@aws-sdk/client-s3'),
        import('@aws-sdk/s3-request-presigner'),
      ]);
      const command = new GetObjectCommand({ Bucket: config.S3_BUCKET, Key: prefix + objectKey });
      return {
        downloadUrl: await getSignedUrl(await getClient(), command, {
          expiresIn: config.PRESIGN_TTL_SECONDS,
        }),
        expiresInSeconds: config.PRESIGN_TTL_SECONDS,
      };
    },
    async put() {
      throw new HttpError(400, 'use_presigned', 'With the S3 driver, upload via the presigned URL.');
    },
    async get() {
      throw new HttpError(400, 'use_presigned', 'With the S3 driver, download via the presigned URL.');
    },
    async remove() {},
  };
}

let driver = null;

export function storage() {
  if (!driver) driver = config.STORAGE_DRIVER === 's3' ? s3Driver() : localDriver();
  return driver;
}

export { buildKey, randomId, assertContentType };
