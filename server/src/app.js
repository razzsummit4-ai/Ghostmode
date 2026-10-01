import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { config } from './config.js';
import { requestLogger } from './logger.js';
import { globalLimiter } from './middleware/rateLimit.js';
import { errorHandler, notFound } from './middleware/error.js';
import authRoutes from './routes/auth.js';
import keyRoutes from './routes/keys.js';
import messageRoutes from './routes/messages.js';
import groupRoutes from './routes/groups.js';
import chatRoutes from './routes/chats.js';
import userRoutes from './routes/users.js';
import mediaRoutes from './routes/media.js';
import { isConnected } from './db.js';

/**
 * Escape text going into the landing page.
 *
 * The one interpolated value is the request's own Host header, which a client
 * can set to anything. Without escaping, a crafted Host would inject markup
 * into the page this server serves. Ampersand is replaced first so the
 * entities this function introduces are not themselves escaped twice.
 */
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const SERVICE_NAME = 'SecureChat E2E Messenger';
const SERVICE_VERSION = '1.0.0';

/**
 * The page a browser sees at the root.
 *
 * Self-contained on purpose: no CDN, no web fonts, no external requests. The
 * server's Content-Security-Policy stays disabled for API traffic, so this
 * page must not be the thing that introduces a third-party origin.
 *
 * @param {string|undefined} host  the Host header the browser used to reach us
 * @param {boolean} dbUp           whether the database is currently connected
 */
function landingPage(host, dbUp) {
  const safeHost = escapeHtml(host || 'ghostmode.onrender.com');
  const status = dbUp
    ? '<span class="ok">&#9679; Server is live &amp; DB connected</span>'
    : '<span class="bad">&#9679; Server is live &amp; DB unreachable</span>';

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>${SERVICE_NAME}</title>
<style>
  body{font-family:system-ui,sans-serif;background:#0b0f14;color:#e6edf3;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
  .card{background:#111820;border:1px solid #1f2a36;border-radius:16px;padding:32px;max-width:480px;width:90%;box-shadow:0 10px 30px rgba(0,0,0,.4)}
  h1{margin:0 0 8px;font-size:24px}
  code{background:#1f2a36;padding:2px 6px;border-radius:6px;word-break:break-all}
  .ok{color:#2fbc82}
  .bad{color:#f85149}
</style>
</head>
<body>
  <div class="card">
    <h1>&#128274; ${SERVICE_NAME}</h1>
    <p>${status}</p>
    <p>API Address to enter in app:</p>
    <p><code>${safeHost}</code></p>
    <p style="opacity:.7;font-size:13px">Version ${SERVICE_VERSION} &middot; Health: /health</p>
    <p style="opacity:.7;font-size:13px;margin-bottom:0">Relays ciphertext and public keys only. Stores no plaintext and holds no private keys.</p>
  </div>
</body>
</html>`;
}

export function createApp() {
  const app = express();

  // Trust the first proxy hop (nginx/Heroku) for correct client IPs in logs.
  app.set('trust proxy', 1);
  app.disable('x-powered-by');

  app.use(
    helmet({
      contentSecurityPolicy: false, // API only; no HTML is served
      crossOriginResourcePolicy: { policy: 'cross-origin' },
    }),
  );

  const origins = config.CORS_ORIGINS.includes('*') ? true : config.CORS_ORIGINS;
  app.use(cors({ origin: origins, methods: ['GET', 'POST', 'PATCH', 'DELETE'], maxAge: 86_400 }));

  // 64 KB is generous for a base64 ciphertext of a text message. Media is
  // uploaded out-of-band via presigned URLs, so it never passes through here.
  app.use(express.json({ limit: '256kb' }));
  app.use(express.urlencoded({ extended: false, limit: '64kb' }));

  // The local media driver needs the raw octet-stream body so it can persist
  // the encrypted blob byte-for-byte. It only applies to the blob PUT path;
  // every other route continues to see parsed JSON.
  app.use(
    '/api/media/blob',
    express.raw({ type: '*/*', limit: config.MEDIA_MAX_BYTES }),
  );

  app.use(requestLogger);
  app.use(globalLimiter);

  /**
 * Service identity at the root.
 *
 * Two audiences reach this URL and they need different things. A person
 * opening it in a browser wants a page explaining what this is and how to
 * connect; a script wants the machine-readable identity the app probes for.
 * Serving HTML to `Accept: text/html` and JSON to everything else gives each
 * one without a second URL or a redirect that would break the app's probe.
 */
app.get('/', (req, res) => {
  const dbUp = isConnected();
  const accept = req.headers.accept || '';

  // Browser asks for a page; the Flutter app and scripts ask for JSON. Both
  // are answered here so neither audience needs a second URL or a redirect.
  if (accept.includes('text/html')) {
    res.set('Content-Type', 'text/html; charset=utf-8');
    return res.status(200).send(landingPage(req.headers.host, dbUp));
  }

  return res.status(200).json({
    ok: true,
    service: 'securechat',
    name: SERVICE_NAME,
    version: SERVICE_VERSION,
    db: dbUp ? 'up' : 'down',
  });
});

  // Reachability probe, used by the app's server picker and by Settings.
  //
  // `ok` and `service` exist for the client: `ok` is the field it checks, and
  // `service` is what lets it tell a SecureChat server apart from some other
  // Node project that happens to hold the same port. Without that marker a
  // foreign server answers 200, the app assumes it is theirs, and every
  // sign-up, sign-in and OTP call then fails with a 404 that says nothing about
  // the real cause.
  app.get('/health', (req, res) => {
    res.json({
      ok: true,
      status: 'ok',
      service: 'securechat',
      version: '1.0.0',
      time: new Date().toISOString(),
      db: isConnected() ? 'up' : 'down',
      uptime: process.uptime(),
    });
  });

  app.use('/api/auth', authRoutes);
  app.use('/api/keys', keyRoutes);
  app.use('/api/messages', messageRoutes);
  app.use('/api/groups', groupRoutes);
  app.use('/api/chats', chatRoutes);
  app.use('/api/users', userRoutes);
  app.use('/api/media', mediaRoutes);

  /**
   * Deliberate anti-goal guard rail.
   * There is intentionally NO endpoint that decrypts a message. If a future
   * contributor adds one, this catches it in review and in tests.
   */
  app.all(/^\/api\/.*decrypt.*/, (req, res) => {
    res.status(404).json({
      error: 'not_found',
      message: 'This server is zero-knowledge: it cannot and will not decrypt messages.',
    });
  });

  app.use(notFound);
  app.use(errorHandler);

  return app;
}
