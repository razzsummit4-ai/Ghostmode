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

  // Service identity at the root.
  //
  // Someone who opens this server in a browser used to land on a bare
  // `{"error":"not_found"}` 404, which reads like a broken deployment rather
  // than a working API server with no web UI. This answers with the same
  // `service: 'securechat'` marker as /health, so the app's server picker and a
  // human looking at the URL can both confirm they reached the right place.
  app.get('/', (req, res) => {
    res.json({
      ok: true,
      service: 'securechat',
      name: 'SecureChat E2E Messenger',
      version: '1.0.0',
      message:
        'This is an API server, not a website. Point the SecureChat app at this ' +
        'address, or see /health for status.',
      endpoints: {
        health: '/health',
        auth: '/api/auth',
        keys: '/api/keys',
        chats: '/api/chats',
        messages: '/api/messages',
        groups: '/api/groups',
        users: '/api/users',
        media: '/api/media',
      },
      db: isConnected() ? 'up' : 'down',
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
