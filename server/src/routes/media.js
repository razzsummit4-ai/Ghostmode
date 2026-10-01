import { Router } from 'express';
import { z } from 'zod';
import { requireAuth } from '../middleware/auth.js';
import { asyncRoute, HttpError } from '../middleware/error.js';
import { mediaLimiter } from '../middleware/rateLimit.js';
import { storage, buildKey, assertContentType } from '../lib/storage.js';
import { config } from '../config.js';
import { logger } from '../logger.js';

const router = Router();

/**
 * POST /api/media/presign
 *
 * Returns a short-lived upload target for an ALREADY ENCRYPTED blob.
 *
 * The client flow is: generate a random AES-256-GCM key -> encrypt the file
 * locally -> upload only the ciphertext -> send the file key inside the
 * message ciphertext. This server therefore receives and stores opaque bytes
 * and has no way to read a client's media.
 */
router.post(
  '/presign',
  requireAuth,
  mediaLimiter,
  asyncRoute(async (req, res) => {
    const body = z
      .object({
        contentType: z.string().max(100).default('application/octet-stream'),
        size: z.number().int().positive().max(config.MEDIA_MAX_BYTES),
        // Non-semantic hint used only to pick a download filename extension.
        // The real name travels inside the encrypted payload.
        kind: z.enum(['image', 'video', 'audio', 'file']).default('file'),
      })
      .parse(req.body);

    const contentType = assertContentType(body.contentType);
    const objectKey = buildKey();
    const target = await storage().createUploadUrl({ objectKey, contentType });

    logger.info('media.presigned', {
      userId: String(req.user._id),
      driver: storage().name,
      bytes: body.size,
      kind: body.kind,
    });

    res.json({
      objectKey,
      uploadUrl: target.uploadUrl,
      method: target.method,
      headers: target.headers,
      expiresInSeconds: target.expiresInSeconds,
      // Echoed so the client can verify what it must set on the PUT.
      contentType,
    });
  }),
);

/**
 * PUT /api/media/blob/:key
 *
 * Local-driver upload target. The client PUTs already-encrypted bytes here.
 * The URL contains only an unguessable random key, so possession of the URL is
 * the authorisation - exactly like an S3 presigned URL.
 */
router.put(
  '/blob/:key(*)',
  // No bearer token by design - the URL's random key is the capability, the
  // same model as an S3 presigned PUT. It does need the media limiter though:
  // this route writes straight to disk, and leaving it unbounded lets an
  // unauthenticated caller fill the volume with a single scripted loop.
  mediaLimiter,
  asyncRoute(async (req, res) => {
    if (storage().name !== 'local') {
      throw new HttpError(404, 'not_found', 'Use a presigned URL with the S3 driver.');
    }
    assertContentType(req.headers['content-type']);
    if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
      throw new HttpError(400, 'empty_upload', 'Upload body must be the encrypted blob.');
    }
    if (req.body.length > config.MEDIA_MAX_BYTES) {
      throw new HttpError(413, 'too_large', 'Encrypted blob exceeds the size limit.');
    }

    await storage().put({
      objectKey: req.params.key,
      buffer: req.body,
      contentType: req.headers['content-type'],
    });
    res.status(200).json({ ok: true, objectKey: req.params.key, bytes: req.body.length });
  }),
);

/** GET /api/media/blob/:key - download encrypted bytes (local driver only). */
router.get(
  '/blob/:key(*)',
  asyncRoute(async (req, res) => {
    if (storage().name !== 'local') {
      throw new HttpError(404, 'not_found', 'Use a presigned download URL.');
    }
    const buffer = await storage().get({ objectKey: req.params.key });
    res.setHeader('content-type', 'application/octet-stream');
    res.setHeader('content-length', String(buffer.length));
    // Opaque blobs must never be sniffed or embedded by a browser.
    res.setHeader('x-content-type-options', 'nosniff');
    res.setHeader('content-disposition', 'attachment');
    res.setHeader('cache-control', 'private, max-age=300');
    res.send(buffer);
  }),
);

export default router;
