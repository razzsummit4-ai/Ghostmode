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
 * into the page this server serves.
 */
const escapeHtml = (value) =>
  String(value).replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c],
  );

/** The endpoint map, shared by the JSON body and the HTML page. */
const PUBLIC_ENDPOINTS = [
  ['GET', '/health', 'Status probe used by the app'],
  ['POST', '/api/auth/register', 'Create an account'],
  ['POST', '/api/auth/login', 'Sign in'],
  ['GET', '/api/auth/me', 'Current identity and key pool'],
  ['GET', '/api/keys/:userId', 'Fetch a contact key bundle'],
  ['POST', '/api/keys/prekeys', 'Top up one-time pre-keys'],
  ['GET', '/api/chats', 'List chats'],
  ['GET', '/api/messages/:chatId', 'Fetch ciphertext history'],
  ['POST', '/api/messages', 'Send an encrypted message'],
  ['GET', '/api/groups', 'List groups'],
  ['GET', '/api/users/:id', 'Public profile'],
  ['POST', '/api/media', 'Request an upload URL'],
];

const SERVICE_NAME = 'SecureChat E2E Messenger';
const SERVICE_VERSION = '1.0.0';

/**
 * True when the caller is a browser asking for a page, not an API client.
 *
 * Browsers send `text/html` with a wildcard fallback; a script sends the
 * wildcard on its own, or `application/json`. Requiring `text/html` therefore
 * keeps the Flutter app and any curl-based tooling on the JSON contract.
 */
const wantsHtml = (req) => (req.headers.accept || '').includes('text/html');

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
  // Show the address the visitor actually typed, so it is correct on every
  // deployment without hard-coding a domain anywhere.
  const address = escapeHtml(host || 'this-server-address');
  const pill = dbUp
    ? '<span class="pill up">operational</span>'
    : '<span class="pill down">database unreachable</span>';

  const rows = PUBLIC_ENDPOINTS.map(
    ([method, path, note]) =>
      `<tr><td><code>${method}</code></td>` +
      `<td><code>${escapeHtml(path)}</code></td>` +
      `<td>${escapeHtml(note)}</td></tr>`,
  ).join('');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${SERVICE_NAME}</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 2.5rem 1.25rem 4rem;
    background: #0d1117; color: #e6edf3;
    font: 16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }
  main { max-width: 46rem; margin: 0 auto; }
  h1 { font-size: 1.7rem; margin: 0 0 .35rem; letter-spacing: -.02em; }
  .sub { color: #8b949e; margin: 0 0 1.75rem; }
  .card {
    background: #161b22; border: 1px solid #30363d; border-radius: 10px;
    padding: 1.25rem 1.35rem; margin-bottom: 1.25rem;
  }
  .card h2 {
    font-size: 1rem; margin: 0 0 .7rem;
    text-transform: uppercase; letter-spacing: .06em; color: #8b949e;
  }
  code, .addr {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: .9em;
  }
  .addr {
    display: block; background: #0d1117; border: 1px solid #30363d;
    border-radius: 6px; padding: .7rem .85rem; margin: .5rem 0 .75rem;
    word-break: break-all; color: #7ee787;
  }
  table { width: 100%; border-collapse: collapse; font-size: .92rem; }
  td, th {
    text-align: left; padding: .5rem .4rem;
    border-bottom: 1px solid #21262d; vertical-align: top;
  }
  th {
    color: #8b949e; font-weight: 600; font-size: .78rem;
    text-transform: uppercase; letter-spacing: .05em;
  }
  td:first-child { white-space: nowrap; }
  td:last-child { color: #8b949e; }
  .pill { display: inline-block; padding: .12rem .6rem; border-radius: 999px; font-size: .8rem; font-weight: 600; }
  .up { background: rgba(46,160,67,.15); color: #3fb950; }
  .down { background: rgba(248,81,73,.15); color: #f85149; }
  .note { color: #8b949e; font-size: .92rem; margin: 0; }
  ol { margin: .4rem 0 0; padding-left: 1.25rem; }
  li { margin-bottom: .3rem; }
  footer { color: #6e7681; font-size: .85rem; text-align: center; margin-top: 2rem; }
</style>
</head>
<body>
<main>
  <h1>${SERVICE_NAME}</h1>
  <p class="sub">Version ${SERVICE_VERSION} &middot; ${pill}</p>

  <div class="card">
    <h2>Connect the app</h2>
    <p class="note">This is a backend, not a website. Open SecureChat on your phone, go to
      <strong>Settings &rarr; Server address</strong>, and enter:</p>
    <code class="addr">${address}</code>
    <p class="note">The app checks <code>/health</code> to confirm it reached a SecureChat
      server before offering it.</p>
  </div>

  <div class="card">
    <h2>Get started</h2>
    <ol>
      <li>Install the APK from the project\'s <code>dist/</code> folder, or build it with
        <code>tools/build-apk.ps1</code>.</li>
      <li>Sign up once with a phone number and password. A number can only be registered once.</li>
      <li>Your private keys are generated on the device and are never sent to this server.</li>
    </ol>
  </div>

  <div class="card">
    <h2>Endpoints</h2>
    <table>
      <thead><tr><th>Method</th><th>Path</th><th>Purpose</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>

  <div class="card">
    <h2>Privacy</h2>
    <p class="note">This server relays ciphertext and public keys only. It stores no plaintext,
      holds no private keys, and has no endpoint that can decrypt a message.</p>
  </div>

  <footer>Machine-readable identity is still available as JSON &mdash; request this URL with
    <code>Accept: application/json</code>.</footer>
</main>
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

  if (!wantsHtml(req)) {
    return res.json({
      ok: true,
      service: 'securechat',
      name: SERVICE_NAME,
      version: SERVICE_VERSION,
      message:
        'This is an API server, not a website. Point the SecureChat app at this ' +
        'address, or see /health for status.',
      endpoints: Object.fromEntries(PUBLIC_ENDPOINTS.map(([, p]) => [p, p])),
      db: dbUp ? 'up' : 'down',
    });
  }

  return res.type('html').send(landingPage(req.headers.host, dbUp));
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
