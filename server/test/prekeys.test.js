import { test, before, after, describe } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { startTestServer, stopTestServer, registerUser, auth, b64, keyBundle } from './helpers.js';

let app;
before(async () => { app = await startTestServer(); });
after(async () => { await stopTestServer(); });
const api = () => request(app);

describe('one-time pre-key pool integrity', () => {
  // Regression test for a bug that only appeared in production.
  //
  // The client used to top up its pool by publishing fresh keys under a fresh
  // 1..n id range while its private halves were stored under 101..n. The server
  // appended without deduplicating, so the pool ended up holding two entries for
  // the same keyId. It then handed out an id whose public key no longer matched
  // the private half the responder looked up locally, and every message in that
  // session failed its GCM tag.
  //
  // The server cannot detect a wrong id on its own - it has no way to know what
  // the device stored - but it CAN refuse to let the pool contain a duplicate
  // keyId, which is the condition that made the mismatch possible.

  test('rejects a top-up that re-publishes an existing keyId', async () => {
    const user = await registerUser(api(), '+10000000701', 71);
    const before = await api().get('/api/auth/me').set(auth(user.token)).expect(200);
    assert.equal(before.body.preKeyHealth.remaining, 5);

    const res = await api()
      .post('/api/keys/prekeys')
      .set(auth(user.token))
      .send({
        // keyId 1 already exists in the pool from registration.
        oneTimePreKeys: [
          { keyId: 1, publicKey: b64(32, 200) },
          { keyId: 2, publicKey: b64(32, 201) },
        ],
      })
      .expect(409);

    assert.equal(res.body.error, 'prekey_id_collision');

    // The pool must be untouched, not half-updated.
    const after = await api().get('/api/auth/me').set(auth(user.token)).expect(200);
    assert.equal(after.body.preKeyHealth.remaining, 5);
  });

  test('accepts a top-up with non-colliding ids', async () => {
    const user = await registerUser(api(), '+10000000702', 72);
    const res = await api()
      .post('/api/keys/prekeys')
      .set(auth(user.token))
      .send({
        oneTimePreKeys: [
          { keyId: 101, publicKey: b64(32, 210) },
          { keyId: 102, publicKey: b64(32, 211) },
        ],
      })
      .expect(200);

    assert.equal(res.body.preKeyCount, 7);
  });

  test('a consumed pre-key id is not handed out again', async () => {
    const alice = await registerUser(api(), '+10000000703', 73);
    const bob = await registerUser(api(), '+10000000704', 74);

    const first = await api()
      .get(`/api/keys/${bob.user.id}?consume=true`)
      .set(auth(alice.token))
      .expect(200);
    assert.equal(first.body.oneTimePreKey.keyId, 1);

    // Bob top-ups starting past his existing range, as a corrected client does.
    await api()
      .post('/api/keys/prekeys')
      .set(auth(bob.token))
      .send({ oneTimePreKeys: [{ keyId: 101, publicKey: b64(32, 220) }] })
      .expect(200);

    // A second handshake must not receive key 1 again.
    const second = await api()
      .get(`/api/keys/${bob.user.id}?consume=true`)
      .set(auth(alice.token))
      .expect(200);
    assert.notEqual(second.body.oneTimePreKey.keyId, 1);
  });
});
