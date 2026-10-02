import { test, before, after, describe } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import {
  startTestServer,
  stopTestServer,
  registerUser,
  auth,
  b64,
} from './helpers.js';

let app;

before(async () => {
  app = await startTestServer();
});
after(async () => {
  await stopTestServer();
});

const api = () => request(app);

const payload = (id, extra = {}) => ({
  clientMessageId: id,
  ciphertext: b64(48, 1),
  iv: b64(12, 2),
  header: { type: 'prekey', preKeyId: 1, signedPreKeyId: 1, baseKey: b64(32, 3) },
  envelope: { type: 'text', attachmentCount: 0, expiresInSeconds: 0 },
  ...extra,
});

describe('messaging', () => {
  test('stores ciphertext and returns it unchanged', async () => {
    const alice = await registerUser(api(), '+10000000301', 21);
    const bob = await registerUser(api(), '+10000000302', 22);

    const sent = await api()
      .post('/api/messages')
      .set(auth(alice.token))
      .send(payload('msg-ciphertext-0001', { receiverId: bob.user.id }))
      .expect(201);

    const { message } = sent.body;
    assert.equal(message.ciphertext, b64(48, 1));
    assert.equal(message.senderId, alice.user.id);
    assert.equal(message.receiverId, bob.user.id);
    assert.equal(message.status, 'sent');

    // The server must not have invented any plaintext field.
    for (const key of ['text', 'body', 'plaintext', 'content']) {
      assert.equal(message[key], undefined, `response must not expose "${key}"`);
    }
  });

  test('a repeated clientMessageId is idempotent, not duplicated', async () => {
    const alice = await registerUser(api(), '+10000000303', 23);
    const bob = await registerUser(api(), '+10000000304', 24);

    const first = await api()
      .post('/api/messages')
      .set(auth(alice.token))
      .send(payload('msg-idempotent-01', { receiverId: bob.user.id }))
      .expect(201);

    const second = await api()
      .post('/api/messages')
      .set(auth(alice.token))
      .send(payload('msg-idempotent-01', { receiverId: bob.user.id }))
      .expect(200);

    assert.equal(second.body.duplicate, true);
    assert.equal(second.body.message.id, first.body.message.id);
  });

  test('a recipient can read the thread and a stranger cannot', async () => {
    const alice = await registerUser(api(), '+10000000305', 25);
    const bob = await registerUser(api(), '+10000000306', 26);
    const eve = await registerUser(api(), '+10000000307', 27);

    await api()
      .post('/api/messages')
      .set(auth(alice.token))
      .send(payload('msg-access-00001', { receiverId: bob.user.id }))
      .expect(201);

    const chatId = [alice.user.id, bob.user.id].sort().join('|');

    const asBob = await api().get(`/api/messages/${chatId}`).set(auth(bob.token)).expect(200);
    assert.equal(asBob.body.messages.length, 1);

    await api().get(`/api/messages/${chatId}`).set(auth(eve.token)).expect(403);
  });

  test('rejects a message with neither receiver nor group', async () => {
    const alice = await registerUser(api(), '+10000000308', 28);
    await api()
      .post('/api/messages')
      .set(auth(alice.token))
      .send(payload('msg-no-dest-0001'))
      .expect(400);
  });

  test('rejects a message addressed to yourself', async () => {
    const alice = await registerUser(api(), '+10000000309', 29);
    const res = await api()
      .post('/api/messages')
      .set(auth(alice.token))
      .send(payload('msg-self-000001', { receiverId: alice.user.id }))
      .expect(400);
    assert.equal(res.body.error, 'cannot_message_self');
  });

  test('rejects a malformed IV', async () => {
    const alice = await registerUser(api(), '+10000000310', 30);
    const bob = await registerUser(api(), '+10000000311', 31);
    const res = await api()
      .post('/api/messages')
      .set(auth(alice.token))
      .send(payload('msg-bad-iv-0001', { receiverId: bob.user.id, iv: '!!!not base64!!!' }))
      .expect(400);
    assert.equal(res.body.error, 'validation_failed');
  });
});

describe('delivery receipts', () => {
  test('delivered and read advance the status', async () => {
    const alice = await registerUser(api(), '+10000000312', 32);
    const bob = await registerUser(api(), '+10000000313', 33);

    const sent = await api()
      .post('/api/messages')
      .set(auth(alice.token))
      .send(payload('msg-receipt-0001', { receiverId: bob.user.id }))
      .expect(201);
    const id = sent.body.message.id;
    const chatId = [alice.user.id, bob.user.id].sort().join('|');

    await api()
      .post('/api/messages/status')
      .set(auth(bob.token))
      .send({ messageIds: [id], status: 'delivered' })
      .expect(200);

    let thread = await api().get(`/api/messages/${chatId}`).set(auth(alice.token)).expect(200);
    assert.equal(thread.body.messages[0].status, 'delivered');
    assert.ok(thread.body.messages[0].deliveredAt);

    await api()
      .post('/api/messages/status')
      .set(auth(bob.token))
      .send({ messageIds: [id], status: 'read' })
      .expect(200);

    thread = await api().get(`/api/messages/${chatId}`).set(auth(alice.token)).expect(200);
    assert.equal(thread.body.messages[0].status, 'read');
  });

  test("a user cannot mark somebody else's message as read", async () => {
    const alice = await registerUser(api(), '+10000000314', 34);
    const bob = await registerUser(api(), '+10000000315', 35);
    const eve = await registerUser(api(), '+10000000316', 36);

    const sent = await api()
      .post('/api/messages')
      .set(auth(alice.token))
      .send(payload('msg-receipt-0002', { receiverId: bob.user.id }))
      .expect(201);

    const res = await api()
      .post('/api/messages/status')
      .set(auth(eve.token))
      .send({ messageIds: [sent.body.message.id], status: 'read' })
      .expect(200);

    assert.equal(res.body.updated, 0, 'eve must not be able to receipt this message');
  });

  test('deletes only your own messages', async () => {
    const alice = await registerUser(api(), '+10000000317', 37);
    const bob = await registerUser(api(), '+10000000318', 38);
    const sent = await api()
      .post('/api/messages')
      .set(auth(alice.token))
      .send(payload('msg-delete-0001', { receiverId: bob.user.id }))
      .expect(201);

    await api().delete(`/api/messages/${sent.body.message.id}`).set(auth(bob.token)).expect(403);
    await api().delete(`/api/messages/${sent.body.message.id}`).set(auth(alice.token)).expect(200);
  });
});

describe('chat list', () => {
  test('returns threads with encrypted previews', async () => {
    const alice = await registerUser(api(), '+10000000401', 41);
    const bob = await registerUser(api(), '+10000000402', 42);

    await api()
      .post('/api/messages')
      .set(auth(alice.token))
      .send(payload('chatlist-msg-001', { receiverId: bob.user.id }))
      .expect(201);

    const res = await api().get('/api/chats').set(auth(bob.token)).expect(200);
    const thread = res.body.chats.find((c) => c.type === 'direct');
    assert.ok(thread, 'bob should see a direct thread');
    assert.equal(thread.peerId, alice.user.id);
    assert.equal(thread.lastMessage.ciphertext, b64(48, 1));
    assert.equal(thread.lastMessage.text, undefined);
  });
});

describe('groups', () => {
  test('creates a group and sends group ciphertext', async () => {
    const alice = await registerUser(api(), '+10000000501', 51);
    const bob = await registerUser(api(), '+10000000502', 52);

    const created = await api()
      .post('/api/groups')
      .set(auth(alice.token))
      .send({ name: 'Team', memberIds: [bob.user.id] })
      .expect(201);

    const groupId = created.body.group.id;
    assert.equal(created.body.group.members.length, 2);
    // No group key material anywhere in the response.
    assert.equal(JSON.stringify(created.body).includes('groupKey'), false);

    const sent = await api()
      .post('/api/messages')
      .set(auth(alice.token))
      .send({
        clientMessageId: 'group-msg-000001',
        groupId,
        ciphertext: b64(64, 9),
        iv: b64(12, 8),
        header: { type: 'group', senderKeyId: 'sk-1', senderIteration: 0 },
        envelope: { type: 'text', attachmentCount: 0, expiresInSeconds: 0 },
      })
      .expect(201);

    assert.equal(sent.body.message.conversationType, 'group');
    assert.equal(sent.body.message.groupId, groupId);

    const list = await api().get('/api/chats').set(auth(bob.token)).expect(200);
    assert.ok(list.body.chats.some((c) => c.type === 'group' && c.groupId === groupId));
  });

  test('a non-member cannot post to a group', async () => {
    const alice = await registerUser(api(), '+10000000503', 53);
    const eve = await registerUser(api(), '+10000000504', 54);
    const created = await api()
      .post('/api/groups')
      .set(auth(alice.token))
      .send({ name: 'Private', memberIds: [] })
      .expect(201);

    await api()
      .post('/api/messages')
      .set(auth(eve.token))
      .send({
        clientMessageId: 'group-msg-intruder1',
        groupId: created.body.group.id,
        ciphertext: b64(32, 1),
        iv: b64(12, 2),
        header: { type: 'group' },
        envelope: { type: 'text', attachmentCount: 0, expiresInSeconds: 0 },
      })
      .expect(403);
  });

  test('a non-member cannot read the group thread', async () => {
    const alice = await registerUser(api(), '+10000000505', 55);
    const eve = await registerUser(api(), '+10000000506', 56);
    const created = await api()
      .post('/api/groups')
      .set(auth(alice.token))
      .send({ name: 'Secret', memberIds: [] })
      .expect(201);

    await api()
      .get(`/api/messages/group:${created.body.group.id}`)
      .set(auth(eve.token))
      .expect(403);
  });
});

describe('media', () => {
  test('presigns an upload and stores the encrypted blob', async () => {
    const alice = await registerUser(api(), '+10000000601', 61);

    const presign = await api()
      .post('/api/media/presign')
      .set(auth(alice.token))
      .send({ contentType: 'application/octet-stream', size: 1024, kind: 'image' })
      .expect(200);

    assert.ok(presign.body.uploadUrl);
    assert.equal(presign.body.method, 'PUT');

    // The client PUTs only ciphertext here.
    const bytes = Buffer.alloc(1024, 0xab);
    await api()
      .put(presign.body.uploadUrl.replace(/^https?:\/\/[^/]+/, ''))
      .set('content-type', 'application/octet-stream')
      .send(bytes)
      .expect(200);

    const got = await api().get(presign.body.uploadUrl.replace(/^https?:\/\/[^/]+/, '')).expect(200);
    assert.deepEqual(Buffer.from(got.body), bytes);
  });

  test('rejects a disallowed content type', async () => {
    const alice = await registerUser(api(), '+10000000602', 62);
    await api()
      .post('/api/media/presign')
      .set(auth(alice.token))
      .send({ contentType: 'text/html', size: 10 })
      .expect(400);
  });
});
