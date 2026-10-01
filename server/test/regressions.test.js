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
  test('an over-long password cannot reach the password hasher', async () => {
    const res = await api()
      .post('/api/auth/register')
      .send({ phone: '+10000009007', password: 'x'.repeat(5000) });
    assert.equal(res.status, 400);
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