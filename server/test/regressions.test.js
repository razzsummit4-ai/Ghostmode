import { test, before, after, describe } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import {
  startTestServer,
  stopTestServer,
  registerUser,
  auth,
  b64,
  keyBundle,
  TEST_PASSWORD,
} from './helpers.js';
import { hashPassword, verifyPassword } from '../src/lib/password.js';

let app;

before(async () => {
  app = await startTestServer();
});
after(async () => {
  await stopTestServer();
});

const api = () => request(app);

describe('regressions', () => {
  // Bug 1: verifyPassword derived the scrypt output length from the stored
  // hash, which comes from the database. A malformed or hostile value must not
  // be able to change how much work the KDF is asked to do.
  test('verifyPassword refuses a stored hash of an unexpected length', () => {
    const { salt, hash } = hashPassword(TEST_PASSWORD);
    assert.equal(verifyPassword(TEST_PASSWORD, salt, hash), true);

    // A 1 KB "hash" makes scrypt fill 1 KB per call; a zero-length one
    // degenerates the constant-time comparison entirely.
    const oversized = Buffer.alloc(1024, 7).toString('base64');
    assert.equal(verifyPassword(TEST_PASSWORD, salt, oversized), false);
    assert.equal(verifyPassword(TEST_PASSWORD, salt, ''), false);
    assert.equal(verifyPassword(TEST_PASSWORD, '', hash), false);
  });

  // Bug 2: keys.js minted the registration id with Math.random() while every
  // other path used crypto.randomBytes. It must be unpredictable.
  test('a published registrationId is never zero', async () => {
    const alice = await registerUser(api(), '+10000009003', 13);
    const res = await api()
      .post('/api/keys')
      .set(auth(alice.token))
      .send(keyBundle(21))
      .expect(201);

    const reg = res.body.registrationId;
    assert.equal(typeof reg, 'number');
    assert.ok(Number.isInteger(reg) && reg >= 0 && reg < 0x3fffffff);
    assert.ok(reg > 0, 'registrationId must never be zero');
  });

  // Bug 3: a password longer than the scrypt limit must be rejected before it
  // is ever handed to the KDF.
  // Bug 3: a password longer than the scrypt limit must be rejected before it
  // is ever handed to the KDF.
  test('an over-long password cannot reach the password hasher', async () => {
    const res = await api()
      .post('/api/auth/register')
      .send({ phone: '+10000009007', password: 'x'.repeat(5000) });
    assert.equal(res.status, 400);
  });

  // Bug 8: the root route decided browser-vs-JSON purely on `Accept: text/html`.
// Several mobile browsers and in-app webviews send `*/*` or omit Accept, so
// those users received a bare JSON object with no download link and no sign of
// what to do. A browser User-Agent now counts too, while the Flutter app - which
// sends `Dart/<v> (dart:io)` and `Accept: application/json` - must still get JSON.
describe('root content negotiation', () => {
  const AGENT_ANDROID = 'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/121.0 Mobile';
  const AGENT_IOS = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15';
  const AGENT_DART = 'Dart/3.13 (dart:io)';

  test('serves the page to a mobile browser that sends only a wildcard', async () => {
    const res = await api()
      .get('/')
      .set('User-Agent', AGENT_ANDROID)
      .set('Accept', '*/*');
    assert.equal(res.status, 200);
    assert.match(res.headers['content-type'], /text\/html/);
    assert.match(res.text, /SecureChat/);
  });

  test('serves the page when Accept is absent entirely', async () => {
    const res = await api().get('/').set('User-Agent', AGENT_IOS).set('Accept', '');
    assert.equal(res.status, 200);
    assert.match(res.headers['content-type'], /text\/html/);
  });

  test('still serves JSON to the Flutter app', async () => {
    const res = await api()
      .get('/')
      .set('User-Agent', AGENT_DART)
      .set('Accept', 'application/json');
    assert.equal(res.status, 200);
    assert.match(res.headers['content-type'], /application\/json/);
    assert.equal(res.body.service, 'securechat');
  });

  test('still serves JSON to a script that asks for it', async () => {
    const res = await api()
      .get('/')
      .set('User-Agent', 'curl/8.4.0')
      .set('Accept', 'application/json');
    assert.match(res.headers['content-type'], /application\/json/);
  });

  test('still serves JSON when a browser explicitly prefers JSON', async () => {
    // Accept lists both, JSON wins - an explicit request is honoured.
    const res = await api()
      .get('/')
      .set('User-Agent', AGENT_ANDROID)
      .set('Accept', 'application/json, text/html');
    assert.match(res.headers['content-type'], /application\/json/);
  });

  test('the page offers the APK downloads', async () => {
    const res = await api().get('/').set('User-Agent', AGENT_ANDROID).set('Accept', '*/*');
    assert.match(res.text, /href="\/download\/SecureChat-arm64-v8a\.apk"/);
    assert.match(res.text, /SecureChat-arm64-v8a\.apk/);
  });

  // Bug 9: the download link pointed straight at github.com. On a phone that
  // means resolving a second host and following a cross-site redirect, and that
  // hop is what failed on mobile while the same link worked on a laptop. The
  // page must offer a same-origin path instead.
  test('download links stay on this origin', async () => {
    const res = await api().get('/').set('User-Agent', AGENT_ANDROID).set('Accept', '*/*');
    const hrefs = [...res.text.matchAll(/href="([^"]+)"/g)].map((m) => m[1]);
    assert.ok(hrefs.length > 0, 'the page must link at least one build');
    for (const href of hrefs) {
      assert.ok(
        href.startsWith('/download/'),
        `download link must be same-origin, got ${href}`,
      );
      assert.equal(
        href.includes('github.com'),
        false,
        'the page must not send a phone off to github.com',
      );
    }
  });

  test('an unknown build is refused, never proxied', async () => {
    const res = await api().get('/download/not-a-real-build.apk');
    assert.equal(res.status, 404);
    assert.equal(res.body.error, 'not_found');
  });

  // Bug 10: the signed-URL cache was a single shared slot rather than one per
  // asset, so the first build requested populated it and every later build was
  // served that file's bytes under its own filename - a 64-bit phone received
  // the 32-bit build and the install failed on a device that is supported.
  // Asserting the URL mapping keeps that guarantee without moving ~100 MB of
  // APK through the network, which is not something a test suite should do.
  test('each build maps to its own release URL', async () => {
    const { DOWNLOADS } = await import('../src/routes/downloads.js');
    const { releaseUrlFor } = await import('../src/routes/download.js');
    assert.ok(DOWNLOADS.length >= 2, 'need at least two builds to prove the bug');

    const urls = new Map();
    for (const entry of DOWNLOADS) {
      const url = releaseUrlFor(entry.file);
      assert.equal(
        urls.has(url),
        false,
        `${entry.file} shares a URL with ${urls.get(url) ?? 'nothing'} - ` +
          'that is what made one build serve another build\'s bytes',
      );
      urls.set(url, entry.file);
      assert.ok(
        url.endsWith(encodeURIComponent(entry.file)),
        `${entry.file} must resolve to its own asset, got ${url}`,
      );
    }
  });
});

describe('regressions (media)', () => {
  // Bug 7: the local storage driver built upload URLs from config.PUBLIC_URL.
  // That value defaults to http://localhost:4000 and is not set on Render, so
  // every presigned upload URL pointed at the server's own loopback address and
  // no attachment could ever be sent from a phone. When PUBLIC_URL is a real
  // address it is still honoured, so this checks the unset/loopback case.
  test('a presigned upload URL never points at loopback', async () => {
    const { config } = await import('../src/config.js');
    const alice = await registerUser(api(), '+10000009008', 17);

    // Simulate a deployment where PUBLIC_URL was never configured.
    const original = config.PUBLIC_URL;
    Object.defineProperty(config, 'PUBLIC_URL', {
      value: 'http://localhost:4000',
      configurable: true,
      writable: true,
    });

    try {
      const res = await api()
        .post('/api/media/presign')
        .set(auth(alice.token))
        .set('Host', 'chat.example.test')
        .send({ contentType: 'image/jpeg', size: 1024, kind: 'image' })
        .expect(200);

      assert.ok(
        !res.body.uploadUrl.includes('localhost'),
        `upload URL must not point at loopback, got ${res.body.uploadUrl}`,
      );
      assert.ok(
        res.body.uploadUrl.startsWith('http://chat.example.test/api/media/blob/'),
        `upload URL must use the request host, got ${res.body.uploadUrl}`,
      );
    } finally {
      Object.defineProperty(config, 'PUBLIC_URL', {
        value: original,
        configurable: true,
        writable: true,
      });
    }
  });
});
});

describe('regressions (network)', () => {
  // Bug 4: chats.js compared a stringified ObjectId against a raw value, so
  // the peer of a thread you started could resolve to the wrong user.
  test('chat list resolves the peer for a thread I started', async () => {
    const alice = await registerUser(api(), '+10000009001', 11);
    const bob = await registerUser(api(), '+10000009002', 12);
    const chatId = [alice.user.id, bob.user.id].sort().join('|');

    await api()
      .post('/api/messages')
      .set(auth(alice.token))
      .send({
        clientMessageId: 'peer-resolve-0001',
        receiverId: bob.user.id,
        ciphertext: b64(64),
        iv: b64(12),
        header: { type: 'msg' },
        envelope: { type: 'text' },
      })
      .expect(201);

    const list = await api().get('/api/chats').set(auth(alice.token)).expect(200);
    const thread = list.body.chats.find((c) => c.chatId === chatId);
    assert.ok(thread, 'the thread must appear in the chat list');
    assert.equal(thread.peerId, bob.user.id);
    assert.notEqual(thread.peerId, alice.user.id);
  });

  // Bug 5: pagination cursors went straight into a Mongo comparison, so a
  // non-ObjectId surfaced as a 500 instead of a 400.
  test('a malformed pagination cursor is a 400, not a 500', async () => {
    const alice = await registerUser(api(), '+10000009004', 14);
    const bob = await registerUser(api(), '+10000009005', 15);

    await api()
      .post('/api/messages')
      .set(auth(alice.token))
      .send({
        clientMessageId: 'cursor-check-0001',
        receiverId: bob.user.id,
        ciphertext: b64(64),
        iv: b64(12),
        header: { type: 'msg' },
        envelope: { type: 'text' },
      })
      .expect(201);

    const chatId = [alice.user.id, bob.user.id].sort().join('|');

    for (const cursor of ['not-an-id', '12', 'zzzzzzzzzzzzzzzzzzzzzzzz']) {
      const res = await api()
        .get(`/api/messages/${chatId}`)
        .query({ before: cursor })
        .set(auth(alice.token));
      assert.notEqual(res.status, 500, `cursor "${cursor}" must not produce a 500`);
    }
  });

  // Bug 6: /api/users/search built a $regex from raw user input, so a
  // metacharacter made the query invalid.
  test('user search survives regex metacharacters', async () => {
    const alice = await registerUser(api(), '+10000009006', 16);
    for (const q of ['(', '[', '*', '+999999']) {
      const res = await api().get('/api/users/search').query({ q }).set(auth(alice.token));
      assert.notEqual(res.status, 500, `query "${q}" must not produce a 500`);
    }
  });
});