import { Router } from 'express';
import { logger } from '../logger.js';
import { RELEASE_TAG, DOWNLOADS } from './downloads.js';

const router = Router();

const APK_CONTENT_TYPE = 'application/vnd.android.package-archive';
const FETCH_TIMEOUT_MS = 120_000;

/**
 * Resolved upstream URL cache.
 *
 * GitHub answers a release-asset request with a 302 to a pre-signed
 * release-assets URL that expires about an hour later. Re-resolving it on
 * every download would mean an extra round-trip per user, so the resolved
 * location is cached for most of its life and refreshed only when it is close
 * to expiring.
 *
 * Only ever holds values fetched from GitHub itself - no request data is part
 * of the key, so this cannot be used to make the server fetch arbitrary URLs.
 */
let cached = { url: null, expiresAt: 0 };

async function resolveUpstream(asset) {
  const now = Date.now();
  if (cached.url && cached.expiresAt - now > 5 * 60_000) return cached.url;

  const releaseUrl = `https://github.com/razzsummit4-ai/Ghostmode/releases/download/${RELEASE_TAG}/${encodeURIComponent(asset)}`;

  const res = await fetch(releaseUrl, {
    redirect: 'follow',
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    headers: { 'User-Agent': 'securechat-server' },
  });

  if (!res.ok) throw new Error(`upstream responded ${res.status}`);

  const signed = new URL(res.url);
  const se = signed.searchParams.get('se');
  const expiresAt = se ? Date.parse(se) : now + 30 * 60_000;

  // Drain and discard so the connection is released rather than left hanging.
  await res.arrayBuffer().catch(() => {});

  cached = { url: res.url, expiresAt };
  logger.info('download.upstream_resolved', { asset, expiresAt: new Date(expiresAt).toISOString() });
  return cached.url;
}

/**
 * GET /download/:asset
 *
 * Streams an installable build through this server instead of redirecting to
 * GitHub.
 *
 * The reason is mobile reliability. A phone that taps a link to github.com has
 * to resolve github.com, follow a 302 to a different host, and then be trusted
 * to keep the download - and on a phone the outcome varies wildly by browser,
 * network and region, which is why the link worked on a laptop and appeared to
 * do nothing on a handset. Proxying means the bytes come from the same origin
 * the user is already on, so there is no cross-site hop to fail.
 *
 * The upstream host is a constant, so nothing here can be steered into
 * fetching an internal address.
 */
router.get('/:asset', async (req, res) => {
  const entry = DOWNLOADS.find((d) => d.file === req.params.asset);
  if (!entry) {
    return res.status(404).json({ error: 'not_found', message: 'No such build.' });
  }

  try {
    const upstream = await resolveUpstream(entry.file);
    const fileRes = await fetch(upstream, {
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      headers: { 'User-Agent': 'securechat-server' },
    });

    if (!fileRes.ok || !fileRes.body) {
      throw new Error(`upstream responded ${fileRes.status}`);
    }

    res.setHeader('Content-Type', APK_CONTENT_TYPE);
    res.setHeader('Content-Length', String(fileRes.headers.get('content-length') ?? entry.bytes));
    // A filename in the header is what makes the phone save it as .apk rather
    // than as an untyped file the installer will refuse.
    res.setHeader('Content-Disposition', `attachment; filename="${entry.file}"`);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    // A published build must never be served stale. GitHub release assets are
    // immutable per tag, so an aggressive cache here would keep handing out a
    // previous APK after a rebuild - and an APK is exactly the kind of thing
    // where "works on my machine" is indistinguishable from "wrong server
    // compiled in". Re-downloading is cheap; installing the wrong build is not.
    res.setHeader('Cache-Control', 'no-cache');

    logger.info('download.started', { asset: entry.file });
    // Streamed, never buffered: a 53 MB universal build must not sit in memory.
    const reader = fileRes.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!res.write(Buffer.from(value))) {
        await new Promise((resolve) => res.once('drain', resolve));
      }
    }
    res.end();
  } catch (err) {
    // A failure here must not leave a half-written file that the phone tries
    // to install, so the error path closes the response before anything else.
    logger.error('download.failed', { asset: entry.file, err: err.message });
    if (!res.headersSent) {
      return res.status(502).json({
        error: 'download_unavailable',
        message: 'The download could not be reached. Please try again.',
      });
    }
    return res.destroy();
  }
});

export default router;