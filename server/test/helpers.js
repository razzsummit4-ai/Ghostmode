import { MongoMemoryServer } from 'mongodb-memory-server';

/**
 * Shared test harness.
 *
 * Spins an in-memory MongoDB, builds the app, and exposes helpers to register
 * users and issue access tokens the way a real client would.
 */
let mongod;
let app;

export async function startTestServer() {
  mongod = await MongoMemoryServer.create();
  process.env.MONGODB_URI = mongod.getUri('securechat_test');
  process.env.NODE_ENV = 'test';
  process.env.JWT_SECRET = 'test-secret-that-is-at-least-32-characters-long';
  process.env.STORAGE_DRIVER = 'local';
  process.env.MEDIA_DIR = './var/test-media';
  process.env.RATE_LIMIT_MAX = '100000';
  process.env.AUTH_RATE_LIMIT_MAX = '100000';
  process.env.MESSAGE_RATE_LIMIT_MAX = '100000';
  // Tests must never reach for the embedded database or the media directory of
  // a real deployment, and AUTO_DB=embedded would otherwise collide with the
  // fixed port the dev server uses.
  process.env.AUTO_DB = 'mongo';
  process.env.MEDIA_DIR = './var/test-media';

  // Imported lazily so config picks up the env set above.
  const { createApp } = await import('../src/app.js');
  const { connect, disconnect } = await import('../src/db.js');
  await connect(process.env.MONGODB_URI, { quiet: true });
  app = createApp();
  return app;
}

export async function stopTestServer() {
  if (app) {
    const { disconnect } = await import('../src/db.js');
    await disconnect();
  }
  if (mongod) await mongod.stop();
}

export function getApp() {
  return app;
}

/** Base64 helper for building synthetic key material. */
export const b64 = (n, fill = 7) => Buffer.alloc(n, fill).toString('base64');

/** Build a syntactically valid public key bundle. */
export function keyBundle(seed = 1) {
  return {
    identityKey: b64(32, seed),
    signedPreKey: {
      keyId: 1,
      publicKey: b64(32, seed + 1),
      signature: b64(64, seed + 2),
    },
    oneTimePreKeys: Array.from({ length: 5 }, (_, i) => ({
      keyId: i + 1,
      publicKey: b64(32, seed + 10 + i),
    })),
  };
}

/** A password that passes the policy, used by every test account. */
export const TEST_PASSWORD = 'correct-horse-9';

/** Register a user and return { token, user, keys }. */
export async function registerUser(request, phone, seed = 1) {
  const keys = keyBundle(seed);

  const verify = await request
    .post('/api/auth/register')
    .send({
      phone,
      password: TEST_PASSWORD,
      publicIdentityKey: keys.identityKey,
      signedPreKey: keys.signedPreKey,
      oneTimePreKeys: keys.oneTimePreKeys,
      displayName: `User ${phone.slice(-4)}`,
    })
    .expect(201);

  return { token: verify.body.token, user: verify.body.user, keys };
}

/** Sign in to an existing account. */
export async function loginUser(request, phone, password = TEST_PASSWORD) {
  const res = await request.post('/api/auth/login').send({ phone, password });
  return res;
}

/**
 * Ensure an account has a verification code, returning it.
 *
 * Every account must create one before anyone can open a conversation with it,
 * so tests that message each other have to satisfy that first.
 */
export async function ensureCode(request, user) {
  const existing = await request
    .get('/api/verification/code')
    .set(auth(user.token))
    .expect(200);
  if (existing.body.code) return existing.body.code;

  const created = await request
    .post('/api/verification/code')
    .set(auth(user.token))
    .send({})
    .expect(200);
  return created.body.code;
}

/**
 * Open the channel between two accounts in both directions.
 *
 * Access is one-directional by design, so this grants A access to B and B
 * access to A. Anything a test sends afterwards passes the gate.
 */
export async function verifyPair(request, a, b) {
  const codeA = await ensureCode(request, a);
  const codeB = await ensureCode(request, b);

  await request
    .post(`/api/verification/${b.user.id}`)
    .set(auth(a.token))
    .send({ code: codeB })
    .expect(200);
  await request
    .post(`/api/verification/${a.user.id}`)
    .set(auth(b.token))
    .send({ code: codeA })
    .expect(200);
}

export const auth = (token) => ({ Authorization: `Bearer ${token}` });
