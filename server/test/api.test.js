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

let app;

before(async () => {
  app = await startTestServer();
});
after(async () => {
  await stopTestServer();
});

const api = () => request(app);

describe('zero-knowledge invariants', () => {
  test('rejects a message body containing a plaintext field', async () => {
    const alice = await registerUser(api(), '+10000000001', 1);
    const bob = await registerUser(api(), '+10000000002', 2);

    const res = await api()
      .post('/api/messages')
      .set(auth(alice.token))
      .send({
        clientMessageId: 'zk-violation-0001',
        receiverId: bob.user.id,
        ciphertext: b64(64),
        iv: b64(12),
        header: { type: 'prekey' },
        // This field must be refused outright.
        plaintext: 'hello there',
      })
      .expect(400);

    assert.equal(res.body.error, 'zero_knowledge_violation');
    assert.equal(res.body.code, 'PLAINTEXT_REJECTED');
  });

  test('rejects a nested plaintext field inside the header', async () => {
    const alice = await registerUser(api(), '+10000000003', 3);
    const bob = await registerUser(api(), '+10000000004', 4);

    const res = await api()
      .post('/api/messages')
      .set(auth(alice.token))
      .send({
        clientMessageId: 'zk-violation-0002',
        receiverId: bob.user.id,
        ciphertext: b64(64),
        iv: b64(12),
        header: { type: 'msg', body: 'leaked' },
      })
      .expect(400);

    assert.equal(res.body.code, 'PLAINTEXT_REJECTED');
  });

  test('rejects private key material on the key upload route', async () => {
    const alice = await registerUser(api(), '+10000000005', 5);
    const res = await api()
      .post('/api/keys')
      .set(auth(alice.token))
      .send({ ...keyBundle(6), privateKey: b64(32, 99) })
      .expect(400);

    assert.equal(res.body.code, 'PLAINTEXT_REJECTED');
  });

  test('there is no endpoint that decrypts a message', async () => {
    const alice = await registerUser(api(), '+10000000006', 6);
    for (const path of [
      '/api/messages/decrypt',
      '/api/messages/000000000000000000000001/decrypt',
      '/api/decrypt',
    ]) {
      const res = await api()
        .post(path)
        .set(auth(alice.token))
        .send({ ciphertext: b64(32) });
      assert.ok(res.status === 404, `${path} should not exist, got ${res.status}`);
    }
  });
});

describe('auth: password accounts', () => {
  test('registers a number with a password and returns a token', async () => {
    const res = await api()
      .post('/api/auth/register')
      .send({ phone: '+10000000101', password: TEST_PASSWORD })
      .expect(201);

    assert.ok(res.body.token, 'a token must be issued');
    assert.equal(res.body.isNewUser, true);
    assert.equal(res.body.user.phone, '+10000000101');
    // The response must never carry credential material.
    const serialised = JSON.stringify(res.body);
    assert.ok(!serialised.includes('passwordHash'));
    assert.ok(!serialised.includes('passwordSalt'));
  });

  test('a phone number can only be registered once', async () => {
    const phone = '+10000000103';
    await api().post('/api/auth/register').send({ phone, password: TEST_PASSWORD }).expect(201);

    // A second attempt must be refused, not silently replace the account.
    const res = await api()
      .post('/api/auth/register')
      .send({ phone, password: 'a-different-one-1' })
      .expect(409);
    assert.equal(res.body.code, 'number_already_registered');

    // The original password must still be the one that works...
    const login = await api()
      .post('/api/auth/login')
      .send({ phone, password: TEST_PASSWORD })
      .expect(200);
    assert.ok(login.body.token);

    // ...and the attempted takeover password must not.
    await api()
      .post('/api/auth/login')
      .send({ phone, password: 'a-different-one-1' })
      .expect(401);
  });

  test('the same number in a different format is still the same account', async () => {
    const phone = '+10000000104';
    await api().post('/api/auth/register').send({ phone, password: TEST_PASSWORD }).expect(201);

    // Spacing and punctuation must not be a way to claim the number twice.
    const res = await api()
      .post('/api/auth/register')
      .send({ phone: '+1 000-000 (0104)', password: TEST_PASSWORD })
      .expect(409);
    assert.equal(res.body.code, 'number_already_registered');
  });

  test('signs in with the correct password', async () => {
    const phone = '+10000000105';
    await api().post('/api/auth/register').send({ phone, password: TEST_PASSWORD }).expect(201);

    const res = await api()
      .post('/api/auth/login')
      .send({ phone, password: TEST_PASSWORD })
      .expect(200);
    assert.ok(res.body.token);
    assert.equal(res.body.isNewUser, false);
  });

  test('a wrong password is indistinguishable from an unknown account', async () => {
    const phone = '+10000000106';
    await api().post('/api/auth/register').send({ phone, password: TEST_PASSWORD }).expect(201);

    const wrongPassword = await api()
      .post('/api/auth/login')
      .send({ phone, password: 'not-the-right-one' })
      .expect(401);
    const noAccount = await api()
      .post('/api/auth/login')
      .send({ phone: '+10000000107', password: 'not-the-right-one' })
      .expect(401);

    // Identical code and message, so the response cannot be used to discover
    // which numbers are registered.
    assert.equal(wrongPassword.body.code, noAccount.body.code);
    assert.equal(wrongPassword.body.message, noAccount.body.message);
    assert.equal(wrongPassword.body.code, 'invalid_credentials');
  });

  test('locks an account after repeated failures', async () => {
    const phone = '+10000000108';
    await api().post('/api/auth/register').send({ phone, password: TEST_PASSWORD }).expect(201);

    for (let i = 0; i < 8; i++) {
      await api()
        .post('/api/auth/login')
        .send({ phone, password: 'wrong-guess-here' })
        .expect(401);
    }

    // The correct password is now refused too, until the lock expires.
    const locked = await api()
      .post('/api/auth/login')
      .send({ phone, password: TEST_PASSWORD })
      .expect(429);
    assert.equal(locked.body.code, 'account_locked');
  });

  test('rejects a weak password at sign-up', async () => {
    for (const password of ['short', '11111111', 'password123', 'qwertyuiop']) {
      const res = await api()
        .post('/api/auth/register')
        .send({ phone: '+10000000222', password })
        .expect(400);
      assert.equal(res.body.code, 'weak_password', `"${password}" must be refused`);
    }
  });

  test('rejects a malformed phone number', async () => {
    const res = await api()
      .post('/api/auth/register')
      .send({ phone: 'not-a-phone', password: TEST_PASSWORD })
      .expect(400);
    assert.equal(res.body.code, 'invalid_phone');
  });

  test('check endpoint reports registration without leaking anything', async () => {
    const phone = '+10000000110';
    await api().post('/api/auth/register').send({ phone, password: TEST_PASSWORD }).expect(201);

    const taken = await api().get(`/api/auth/check/${phone}`).expect(200);
    assert.equal(taken.body.registered, true);

    const free = await api().get('/api/auth/check/+10000000111').expect(200);
    assert.equal(free.body.registered, false);
  });

  test('changing a password requires the current one', async () => {
    const phone = '+10000000112';
    const created = await api()
      .post('/api/auth/register')
      .send({ phone, password: TEST_PASSWORD })
      .expect(201);
    const token = created.body.token;

    // A wrong current password must not change anything.
    await api()
      .post('/api/auth/change-password')
      .set(auth(token))
      .send({ currentPassword: 'not-it-at-all', newPassword: 'a-brand-new-one-7' })
      .expect(401);

    await api()
      .post('/api/auth/change-password')
      .set(auth(token))
      .send({ currentPassword: TEST_PASSWORD, newPassword: 'a-brand-new-one-7' })
      .expect(200);

    // The new password works, the old one does not.
    await api()
      .post('/api/auth/login')
      .send({ phone, password: 'a-brand-new-one-7' })
      .expect(200);
    await api()
      .post('/api/auth/login')
      .send({ phone, password: TEST_PASSWORD })
      .expect(401);
  });

  test('requires a bearer token for protected routes', async () => {
    await api().get('/api/auth/me').expect(401);
    await api().get('/api/chats').expect(401);
  });

  test('rejects a forged token', async () => {
    const res = await api().get('/api/auth/me').set(auth('not.a.jwt')).expect(401);
    assert.equal(res.body.error, 'unauthorized');
  });
});
describe('key distribution', () => {
  test('publishes public keys and reports pre-key health', async () => {
    const alice = await registerUser(api(), '+10000000201', 11);
    assert.equal(alice.user.preKeyCount, 5);

    const res = await api().get('/api/auth/me').set(auth(alice.token)).expect(200);
    assert.equal(res.body.preKeyHealth.remaining, 5);
    assert.equal(res.body.user.publicIdentityKey, alice.keys.identityKey);
  });

  test('a key bundle containing a private half is refused', async () => {
    const alice = await registerUser(api(), '+10000000202', 12);
    const res = await api()
      .post('/api/keys')
      .set(auth(alice.token))
      .send({ ...keyBundle(13), identityPrivateKey: b64(32, 3) })
      .expect(400);
    assert.equal(res.body.code, 'PLAINTEXT_REJECTED');
  });

  test('rejects a malformed base64 key length', async () => {
    const alice = await registerUser(api(), '+10000000203', 14);
    const bad = keyBundle(15);
    bad.identityKey = b64(16); // too short
    const res = await api().post('/api/keys').set(auth(alice.token)).send(bad).expect(400);
    assert.equal(res.body.error, 'invalid_key_length');
  });

  test('consuming a pre-key removes it so it can never be replayed', async () => {
    const alice = await registerUser(api(), '+10000000204', 16);
    const bob = await registerUser(api(), '+10000000205', 17);

    const before = await api().get(`/api/keys/${bob.user.id}`).set(auth(alice.token)).expect(200);
    assert.equal(before.body.preKeyCount, 5);

    const first = await api()
      .get(`/api/keys/${bob.user.id}?consume=true`)
      .set(auth(alice.token))
      .expect(200);
    assert.ok(first.body.oneTimePreKey.publicKey);
    assert.equal(first.body.oneTimePreKey.keyId, 1);

    const second = await api()
      .get(`/api/keys/${bob.user.id}?consume=true`)
      .set(auth(alice.token))
      .expect(200);
    // The consumed key is gone, so the next handshake gets a different one.
    assert.equal(second.body.oneTimePreKey.keyId, 2);

    const after = await api().get(`/api/keys/${bob.user.id}`).set(auth(alice.token)).expect(200);
    assert.equal(after.body.preKeyCount, 3);
  });

  test('a device cannot consume its own pre-key', async () => {
    const alice = await registerUser(api(), '+10000000206', 18);
    await api()
      .get(`/api/keys/${alice.user.id}?consume=true`)
      .set(auth(alice.token))
      .expect(400);
  });

  test('directory lookup never exposes raw one-time pre-keys', async () => {
    const alice = await registerUser(api(), '+10000000207', 19);
    const bob = await registerUser(api(), '+10000000208', 20);
    const res = await api().get(`/api/keys/${bob.user.id}`).set(auth(alice.token)).expect(200);
    assert.equal(res.body.oneTimePreKey, undefined);
    assert.ok(res.body.signedPreKey.publicKey);
    assert.ok(res.body.publicIdentityKey);
  });
});
