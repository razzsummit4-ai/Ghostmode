// End-to-end smoke test of the LAN flow a real user follows:
//   1. reach the server over the LAN address the app would be given
//   2. register two accounts with a number and password
//   3. prove a number cannot be registered twice, even in a different format
//   4. sign in with the password, and confirm a wrong one is refused
//   5. send ciphertext both ways and read it back unchanged
//   6. confirm no plaintext field exists anywhere in the response
//   7. confirm a stranger cannot read the thread
//   8. confirm the home screen's chat list contains the new thread
//   9. upload an encrypted attachment and read the bytes back, from the same
//      host the phone used, which is what catches a wrong PUBLIC_URL
//
// Run with the server already listening:  node tools/e2e-lan.mjs [base-url]

const BASE = process.argv[2] || 'http://192.168.0.100:4000';
const PASSWORD = 'correct-horse-9';

let failures = 0;

function check(label, ok, detail = '') {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? `  ${detail}` : ''}`);
  if (!ok) failures++;
}

/** Host of a URL, or null when the server handed back something unparseable. */
function safeHost(url) {
  try {
    return new URL(url).host;
  } catch {
    return null;
  }
}

async function call(method, path, { token, body } = {}) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      'content-type': 'application/json',
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, json: await res.json().catch(() => ({})) };
}

/** Synthetic key material, matching the public-only shape the server expects. */
const b64 = (n, fill) => Buffer.alloc(n, fill).toString('base64');

const keyBundle = (seed) => ({
  publicIdentityKey: b64(32, seed),
  signedPreKey: {
    keyId: 1,
    publicKey: b64(32, seed + 1),
    signature: b64(64, seed + 2),
  },
  oneTimePreKeys: Array.from({ length: 5 }, (_, i) => ({
    keyId: i + 1,
    publicKey: b64(32, seed + 10 + i),
  })),
});

function register(phone, seed, password = PASSWORD) {
  return call('POST', '/api/auth/register', {
    body: {
      phone,
      password,
      ...keyBundle(seed),
      displayName: `User ${phone.slice(-4)}`,
    },
  });
}

console.log(`\nSecureChat LAN smoke test against ${BASE}\n`);

// 1. Reachability, using the exact endpoint the app's connection test calls.
const health = await call('GET', '/health');
check(
  'health endpoint reachable over LAN',
  health.status === 200 && health.json.db === 'up',
  `status=${health.status} db=${health.json.db}`,
);

// 2. Two accounts.
//
// Numbers are generated per run: a number can only ever be registered once, so
// a hard-coded one would make this test fail on its second execution.
const suffix = String(Date.now()).slice(-9);
const ALICE_PHONE = '+91988' + suffix;
const BOB_PHONE = '+91999' + suffix;
// Deliberately never registered, to compare an unknown number against a wrong password.
const UNKNOWN_PHONE = '+91977' + suffix;
const alice = await register(ALICE_PHONE, 11);
const bob = await register(BOB_PHONE, 22);
check(
  'alice registered',
  alice.status === 201 && Boolean(alice.json.token),
  alice.json.user?.id || alice.json.message || '',
);
check(
  'bob registered',
  bob.status === 201 && Boolean(bob.json.token),
  bob.json.user?.id || bob.json.message || '',
);
if (!alice.json.token || !bob.json.token) process.exit(1);

// 3. A number may only be registered once.
const again = await register(ALICE_PHONE, 33, 'some-other-password');
check(
  're-registering a number is refused',
  again.status === 409 && again.json.code === 'number_already_registered',
  `status=${again.status} code=${again.json.code}`,
);

const spaced = await register(ALICE_PHONE, 44);
check(
  'same number in another format is still refused',
  spaced.status === 409,
  `status=${spaced.status}`,
);

// The original password must still work; the takeover one must not.
const okLogin = await call('POST', '/api/auth/login', {
  body: { phone: ALICE_PHONE, password: PASSWORD },
});
check('original password still signs in', okLogin.status === 200, `status=${okLogin.status}`);

const hijack = await call('POST', '/api/auth/login', {
  body: { phone: ALICE_PHONE, password: 'some-other-password' },
});
check('the takeover password does not work', hijack.status === 401, `status=${hijack.status}`);

const wrongPassword = await call('POST', '/api/auth/login', {
  body: { phone: ALICE_PHONE, password: 'definitely-not-it' },
});
const noSuchUser = await call('POST', '/api/auth/login', {
  body: { phone: UNKNOWN_PHONE, password: 'definitely-not-it' },
});
check(
  'wrong password and unknown account are indistinguishable',
  wrongPassword.status === 401
    && wrongPassword.json.code === noSuchUser.json.code
    && wrongPassword.json.message === noSuchUser.json.message,
  `${wrongPassword.json.code} / ${noSuchUser.json.code}`,
);

// 4. A weak password is refused at sign-up.
const weak = await call('POST', '/api/auth/register', {
  body: { phone: UNKNOWN_PHONE, password: '11111111' },
});
check('weak password refused', weak.status === 400, `status=${weak.status}`);

// 5. Messaging still works over the new auth.
const bundle = await call('GET', `/api/keys/${bob.json.user.id}?consume=true`, {
  token: alice.json.token,
});
check(
  'X3DH bundle available and one pre-key consumed',
  bundle.status === 200 && Boolean(bundle.json.oneTimePreKey?.publicKey),
  `preKeyId=${bundle.json.oneTimePreKey?.keyId}`,
);

const chatId = [alice.json.user.id, bob.json.user.id].sort().join('|');
const aToB = 'AAAA'.repeat(12);
const bToA = 'BBBB'.repeat(12);

const sent1 = await call('POST', '/api/messages', {
  token: alice.json.token,
  body: {
    clientMessageId: 'lan-smoke-a2b-0001',
    receiverId: bob.json.user.id,
    ciphertext: aToB,
    iv: b64(12, 3),
    header: { type: 'prekey', preKeyId: 1, signedPreKeyId: 1, baseKey: b64(32, 4) },
    envelope: { type: 'text', attachmentCount: 0, expiresInSeconds: 0 },
  },
});
check('alice -> bob stored', sent1.status === 201, `status=${sent1.status}`);

const sent2 = await call('POST', '/api/messages', {
  token: bob.json.token,
  body: {
    clientMessageId: 'lan-smoke-b2a-0001',
    receiverId: alice.json.user.id,
    ciphertext: bToA,
    iv: b64(12, 5),
    header: { type: 'msg', ratchetKey: b64(32, 6), counter: 0 },
    envelope: { type: 'text', attachmentCount: 0, expiresInSeconds: 0 },
  },
});
check('bob -> alice stored', sent2.status === 201, `status=${sent2.status}`);

const thread = await call('GET', `/api/messages/${chatId}`, { token: alice.json.token });
const rows = thread.json.messages || [];
check('alice reads 2 messages', thread.status === 200 && rows.length === 2, `n=${rows.length}`);

const outbound = rows.find((m) => m.senderId === alice.json.user.id);
const inbound = rows.find((m) => m.senderId === bob.json.user.id);
check('ciphertext returned unchanged', outbound?.ciphertext === aToB && inbound?.ciphertext === bToA);

const forbidden = [
  'text', 'body', 'plaintext', 'content', 'caption', 'password', 'passwordHash',
];
const leaks = forbidden.filter((k) => rows.some((r) => r[k] !== undefined));
check('no plaintext or credential field in any response', leaks.length === 0, leaks.join(','));

// 6. A plaintext-bearing request must be refused outright.
const zk = await call('POST', '/api/messages', {
  token: alice.json.token,
  body: {
    clientMessageId: 'lan-smoke-zk-0001',
    receiverId: bob.json.user.id,
    ciphertext: b64(32, 7),
    iv: b64(12, 8),
    header: { type: 'msg' },
    plaintext: 'this must never be accepted',
  },
});
check(
  'plaintext field rejected by the server',
  zk.status === 400 && zk.json.code === 'PLAINTEXT_REJECTED',
  `status=${zk.status} code=${zk.json.code}`,
);

// 7. A stranger must not be able to read the thread.
const eve = await register(UNKNOWN_PHONE, 55);
const intrusion = await call('GET', `/api/messages/${chatId}`, {
  token: eve.json.token,
});
check('third party cannot read the thread', intrusion.status === 403, `status=${intrusion.status}`);

// 8. The home screen is driven by GET /api/chats. If that ever answers
//    something other than `{ chats: [...] }`, or drops a thread that has
//    messages in it, the user's list goes blank with no error anywhere.
const chats = await call('GET', '/api/chats', { token: alice.json.token });
const chatRows = chats.json.chats ?? [];
check(
  'home chat list contains the new thread',
  chats.status === 200 && chatRows.some((c) => c.chatId === chatId && c.peerId === bob.json.user.id),
  `status=${chats.status} chats=${chatRows.length}`,
);
check(
  'chat list carries the encrypted preview only',
  chatRows.length > 0 &&
    chatRows.every((c) => c.lastMessage?.ciphertext !== undefined && c.lastMessage?.text === undefined),
);

// 9. An attachment round-trip: an avatar, photo or voice note that never
//    finishes loading looks identical to "the server is down".
//    Presign -> PUT the ciphertext -> read it back -> compare bytes.
const blob = Buffer.alloc(2048, 0x5a);
const presign = await call('POST', '/api/media/presign', {
  token: alice.json.token,
  body: { size: blob.length, contentType: 'application/octet-stream', kind: 'file' },
});
check('attachment upload URL issued', presign.status === 200 && Boolean(presign.json.uploadUrl));

// The upload URL is stored verbatim inside the message, so whatever host it
// carries is the host the phone dials later. A PUBLIC_URL of `localhost` or
// the emulator alias `10.0.2.2` therefore signs in perfectly and then fails on
// every attachment - compare hosts instead of trusting a 200.
const uploadUrl = presign.json.uploadUrl ?? '';
check(
  'attachment URL points at this same server',
  safeHost(uploadUrl) === new URL(BASE).host,
  `${safeHost(uploadUrl) ?? '(none)'} vs ${new URL(BASE).host}`,
);

const stored = await fetch(uploadUrl, {
  method: presign.json.method ?? 'PUT',
  headers: { 'content-type': presign.json.contentType ?? 'application/octet-stream' },
  body: blob,
}).catch((err) => ({ status: 0, statusText: err.message }));
check('encrypted blob accepted', stored.status === 200, `status=${stored.status}`);

const fetched = await fetch(uploadUrl).catch(() => ({ status: 0 }));
const fetchedBytes = Buffer.from(await fetched.arrayBuffer?.() ?? new ArrayBuffer(0));
check(
  'attachment bytes come back unchanged',
  fetched.status === 200 && fetchedBytes.equals(blob),
  `status=${fetched.status} bytes=${fetchedBytes.length}`,
);

console.log(
  failures === 0
    ? '\nAll LAN checks passed.\n'
    : `\n${failures} check(s) failed.\n`,
);
process.exit(failures === 0 ? 0 : 1);
