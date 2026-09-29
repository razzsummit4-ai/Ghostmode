# SecureChat — End-to-End Encrypted Messenger

A WhatsApp/Signal-style messenger where the server is **zero-knowledge**: it
stores ciphertext and public keys, and holds nothing that could decrypt a
message. Private keys are generated on the device and never leave it.

```
Flutter (Android/iOS)  ──REST + Socket.io──▶  Node.js  ──▶  MongoDB + S3
   all crypto here                              stores only
   X3DH · Double Ratchet · AES-256-GCM          ciphertext + public keys
```

---

## 1. The one rule everything else follows

**The server must never be able to read a message.**

That rule is enforced in five independent places, so a mistake in one layer
does not silently break the guarantee:

| Layer | Enforcement |
|---|---|
| **Client** | Plaintext is produced and consumed in exactly one place (`service/messaging.dart`) and never written to disk or a log |
| **Transport** | Every request body is ciphertext; there is no plaintext field to send |
| **HTTP layer** | `zeroKnowledgeGuard()` rejects any request containing `text`, `body`, `plaintext`, `content`, `privateKey`, … before a route handler runs |
| **Database** | The Mongoose `Message` schema is `strict: 'throw'` and has no plaintext field; a `pre('validate')` hook re-runs the guard |
| **Socket** | Typing and receipt payloads pass the same guard as the REST API |

There is deliberately **no endpoint that decrypts a message** — `app.js` even
registers a catch-all that 404s any route matching `/decrypt` so one cannot be
added by accident.

---

## 2. How accounts and keys work

### 2.0 Accounts: one number, one password, registered once

Authentication is a phone number plus a password. There is no SMS code.

```
  first time                      every time after
  ──────────                      ────────────────
  POST /api/auth/register         POST /api/auth/login
    { phone, password }             { phone, password }
         │                                 │
         ├─ 409 if the number                ├─ 401 if wrong (identical
         │   is already taken                │   message whether or not
         │                                    │   the account exists)
         └─ scrypt hash + random salt        └─ 401 after 8 failures
            stored; password never              → 15 minute lock
            stored, logged or returned
```

**A number can be registered exactly once, permanently.** The rule holds in
three layers, so no single mistake breaks it:

1. Numbers are normalised to E.164 first, so `+91 90000 00001`,
   `+919000000001` and `+91-90000-00001` are all one account. Without this an
   attacker could claim the same number by adding a space.
2. `POST /api/auth/register` checks and returns **409** if the number exists.
   The existing account is never modified, so this endpoint cannot be used to
   take over a number that is already in use.
3. A **unique index** on `phone` in MongoDB is the authoritative guard, and
   the duplicate-key error is translated into the same 409. That closes the
   race where two registrations arrive simultaneously.

If a number is already registered, the app detects it and switches the user to
the sign-in form rather than letting them fill in a sign-up that will fail.

What is stored: a scrypt hash (N=2^15, r=8 — memory-hard, ~32 MB and ~100 ms
per guess) and a 16-byte random salt. What is never stored, logged or returned:
the password itself. Both fields are `select: false` in the schema, so they
cannot leak through an ordinary query.

Two protections against guessing, layered:

| Layer | Limit | Stops |
|---|---|---|
| `authLimiter` | per-IP, `AUTH_RATE_LIMIT_MAX` per minute | bulk spray from one host |
| Per-account lock | 8 failures → 15 min lock | a slow grind on one account from many IPs |

The lock lives on the user document, so restarting the server does not hand an
attacker a fresh budget. A wrong password and an unknown account also return
identical text, and the unknown-account path still performs a scrypt run, so
neither the message nor the response time reveals which numbers are registered.

**There is no password reset.** That is a deliberate consequence, not an
oversight: a reset flow needs a channel to prove ownership, and this design has
none. A forgotten password means the account cannot be recovered. Adding reset
later means adding proof of number ownership back — a different design.

### 2.1 First install — what is created on the device

```
Device (Flutter)                                  Server (MongoDB)
──────────────────                                ──────────────────
Identity Key Pair  (Ed25519)
  IK_priv ─┐  stored in Keystore/Keychain
  IK_pub  ─┼───────────────────────────────▶  publicIdentityKey
           │
Signed Pre Key   (X25519)
  SPK_priv ─┐ stored in Keystore/Keychain
  SPK_pub  ─┼──────────────▶ signedPreKey { publicKey, keyId }
  signature ◀┘ sign(SPK_pub, IK_priv)      signature ← verified against IK_pub

100 One-Time Pre Keys (X25519)
  OPK_priv ─┐ stored in Keystore/Keychain
  OPK_pub  ─┼──────────────▶ oneTimePreKeys[]  (public halves only)
```

**Private halves never leave the device.** The server's guard rejects a request
containing a private key outright, and `KeyVault.publicBundleForUpload()` has no
field that could hold one.

### 2.2 X3DH handshake — establishing a shared secret

Alice starts a chat with Bob and fetches his bundle
(`GET /api/keys/:id?consume=true`, which atomically burns one one-time pre-key
so it can never be replayed):

```
   Alice's device                          Bob's device
   ──────────────                          ────────────
   fetch Bob's IK, SPK, OPK
   (public halves only)

   generate ephemeral EK_A

   DH1 = DH(IK_A,   SPK_B)   ┐
   DH2 = DH(EK_A,   IK_B)    │  concatenation
   DH3 = DH(EK_A,   SPK_B)   │  in this exact order
   DH4 = DH(EK_A,   OPK_B)   ┘

   SK = HKDF-SHA256(DH1‖DH2‖DH3‖DH4, "SecureChat/X3DH/v1")

   AD = IK_A ‖ IK_B          (binds the session to both identities)

                    ──header: {preKeyId, signedPreKeyId, baseKey}──▶

                          recomputes DH1..DH4 from its own private halves
                          and arrives at the identical SK
```

The four DH values are wiped immediately after use. The ephemeral private key
is **kept** as Alice's first ratchet key pair (the "base key") — the spec
requires it, and it never leaves the device.

#### Why the `preKeyId` has to agree on both sides

DH4 is the only term that needs a **one-time** pre-key, and it is the one term
the two sides do not compute identically — Alice uses the *public* half she
fetched, Bob uses the *private* half he looks up locally by `preKeyId`. The two
halves are joined by that integer alone.

If the id published to the server ever stops matching the id the private half
was stored under, Bob recovers a different key, DH4 differs, and both sides
derive different secrets. Nothing warns you: the first message simply fails its
GCM tag, which the UI used to report as a bare "integrity check" — a message
that reads like tampering when it is really a bookkeeping mismatch.

Three things hold this together, and each has a test:

- `mintOneTimePreKeys()` returns the id it actually stored under, and
  `publicBundleForUpload()` requires it. Ids are a *continuing* counter, so a
  top-up publishes 101..150 rather than restarting at 1.
- The server rejects a top-up that re-uses a `keyId` (`409 prekey_id_collision`)
  instead of appending it. It cannot tell whether an id is *correct*, only
  whether it is *ambiguous* — and ambiguity is the condition that makes the
  mismatch possible.
- The responder treats a missing `preKeyId` as a hard `missing_prekey` error
  rather than silently dropping DH4. Substituting zeros would produce a
  different secret and the same opaque failure, one layer further away.


### 2.3 Double Ratchet — every message gets a new key

From the shared secret:

```
rootKey        = HKDF(SK,   "RatchetRoot/v1")
sendingChain   = HKDF(rootKey, "ChainA/v1")   ← Alice sends
receivingChain = HKDF(rootKey, "ChainB/v1")   ← Alice receives
```

For **each** message:

```
messageKey    = HMAC(chainKey, 0x01)
nextChainKey  = HMAC(chainKey, 0x02)
chainKey      = nextChainKey                 ← chain advances on both sides
ciphertext||tag = AES-256-GCM(messageKey, nonce=random 12B, aad=header‖AD)
```

**Perfect forward secrecy:** the chain key is advanced and persisted *before*
the next message key is derived, so a key is used exactly once. Deleting the
chain keys (logout, key rotation) makes all prior messages permanently
undecryptable — including on the device that sent them.

When either side sends with a fresh ratchet key, both perform one DH step:

```
Alice: rootKey' , chain' = HKDF(rootKey, DH(IK_new, SPK_B))
Bob:   rootKey' , chain' = HKDF(rootKey, DH(IK_A,    SPK_new))
```

X25519 commutativity makes these identical.

### 2.4 The header is authenticated, not just encrypted

`ciphertext || mac` is sealed with `aad = canonicalJSON(header) ‖ AD`. Editing
the counter or ratchet key in transit breaks the GCM tag, so a middleman cannot
replay a message under a different counter. The header is also sorted
canonically, so both devices authenticate byte-identical AAD.

### 2.5 Group chat — Sender Key

Each member generates its own chain. The sender key is distributed to every
other member over the **existing pairwise E2E sessions**, so only the intended
recipient can install it. Group messages are then sealed with a key derived
from that chain, which advances per message.

The server routes group ciphertext and holds no key that opens it. Forward
secrecy holds inside the group too.

### 2.6 Media

```
file -> random AES-256-GCM file key -> sealed on device
     -> only ciphertext uploaded (S3 presigned PUT, or local driver)
     -> file key + filename + mime travel INSIDE the encrypted message body
```

The storage backend holds bytes it cannot read; the key that can read them
exists only inside an E2E session.

### 2.7 Safety number

The 60-digit fingerprint both parties compare:

```
digest = SHA-512( min(IK_A, IK_B) || max(IK_A, IK_B) )
digits = 30 x uint16(digest) mod 100000, grouped as 12 x "NNNNN"
```

Both devices sort the two keys identically, so they independently arrive at the
same digits. A middleman who substituted either key cannot produce matching
digits, which is exactly what a voice or in-person comparison detects.

### 2.8 Offline mesh — NOT encrypted, and labelled as such

`ui/offline_ghost_screen.dart` is a peer-to-peer channel over the Nearby
Connections API for the case where the server is unreachable. Select **ALL** to
broadcast to every phone in range, or one device to send only to it.

```
phone A ─┐
phone B ─┼─ BLE / Wi-Fi Direct, no server ─ broadcast + multi-hop relay
phone C ─┘
```

**The payload is plain UTF-8 text. There is no cipher on this channel.**

```
{ "id": "...", "from": "ghost_4821", "to": "ALL",
  "type": "broadcast", "text": "meet me at 6", "time": "..." }
```

Everything in §2.1–2.7 does **not** apply here. Specifically:

- No X3DH, so there is no authenticated peer — the `ghost_NNNN` name is a random
  session label anyone can claim. It is deliberately not the account identity,
  because reusing a real name would imply a trust relationship that does not
  exist.
- No Double Ratchet, so there is no forward secrecy and no key separation.
- Messages are **relayed** by intermediate devices, so even a future
  "direct" send is forwarded hop by hop rather than delivered point to point.

Anyone running this app in radio range, or any device tapping the same traffic,
reads the content. The screen states this three ways so it cannot be missed: a
permanent red banner, "(unencrypted)" in the composer hint, and "readable by
relays" where an encrypted bubble would show a padlock.

Treat it as a convenience for the no-signal case, not a security boundary. To
promote it, the packet body must become a ciphertext envelope authenticated
against the recipient's identity key, and relays must be unable to read it —
at which point `mesh/ble_mesh.dart` already has the framing to carry it.

The dependency is vendored at `third_party/flutter_nearby_connections` because
the published 1.1.2 is unmaintained and does not build on Gradle 8; that
directory's `android/build.gradle` documents the two changes made.

---

## 3. Layout

```
app/                          Flutter client
  lib/crypto/                 pure crypto, no I/O, fully unit tested
    curve.dart                Ed25519 -> X25519 (RFC 7748 section 6.1)
    kdf.dart                  HKDF + HMAC, ProtocolException
    keys.dart                 CSPRNG, key pairs, identity keys, wipe()
    x3dh.dart                 handshake, initiator + responder
    ratchet.dart              Double Ratchet, skipped keys, persistence
    sender_key.dart           group Sender Key chains
    media_crypto.dart         encrypt-then-upload for attachments
    safety.dart               60-digit safety number
  lib/store/key_vault.dart    ALL private key material (Keystore/Keychain)
  lib/session/                X3DH + ratchet orchestration, identity pinning
  lib/service/                messaging (encrypt/decrypt), groups, secure window
  lib/net/                    REST client, Socket.io gateway, LAN discovery
  lib/services/
    offline_ghost_service.dart offline mesh — PLAINTEXT, see §2.8
  lib/ui/                     screens and widgets
    offline_ghost_screen.dart  offline mesh UI, with permanent warning banner
  test/                       17 crypto tests (no mocks, real handshakes)

server/                       zero-knowledge Node.js backend
  src/middleware/             JWT auth, rate limit, zero-knowledge guard
  src/routes/                 auth, keys, messages, chats, groups, users, media
  src/models/                 Mongoose schemas, strict:'throw'
  src/lib/zero-knowledge.js   the shared plaintext detector
  src/lib/discovery.js        UDP broadcast responder (finds it on the LAN)
  test/                       API + messaging tests, in-memory MongoDB

third_party/
  flutter_nearby_connections/ vendored: Gradle 8 + Flutter 3 fixes, see §2.8
```

---

## 4. Running it

### Server — one command, nothing else to install

```bash
cd server
cp .env.example .env     # set JWT_SECRET to 32+ random characters
npm install
npm start
```

That is the whole setup. `AUTO_DB=embedded` (the default in `.env.example`)
starts a MongoDB inside the server process and stores its data in `./var/db`, so
there is no separate database to install or administer. To use a real MongoDB
instead, set `AUTO_DB=mongo` and point `MONGODB_URI` at it.

#### Using a managed database (MongoDB Atlas)

The embedded database is tied to the machine it runs on. Move to a managed
cluster when the server should survive that machine being wiped or replaced, or
when someone else has to be able to point a client at the same data.

1. [atlas.mongodb.com](https://atlas.mongodb.com) → a free **M0** cluster.
2. **Security → Database Access → Add New Database User**: a name, a password,
   role *Read and write to any database*.
3. **Security → Network Access → Add IP Address**. `0.0.0.0/0` allows every
   address on the internet to try that password. On a home connection prefer
   adding this machine's public IP, which `npm run check:db` prints for you —
   though a broadband IP that changes is exactly why people reach for `0.0.0.0/0`.
4. **Connect → Drivers → Node.js**, and copy the connection string. Copy it
   rather than retyping it: the password has to be URL-encoded inside the URI
   (`Secure@123` → `Secure%40123`), and an unencoded `@` silently truncates the
   hostname, which Atlas reports as a timeout rather than as a typo.
5. Paste it into `MONGODB_URI` in `server/.env`, set `AUTO_DB=mongo`, and check
   it before restarting anything:

```bash
npm run check:db -- "mongodb+srv://…"
npm run check:db              # tests MONGODB_URI once it is in .env
npm run migrate:db -- --dry-run
npm run migrate:db
```

`check:db` separates the layers a single "connection timed out" hides: the shape
of the URI, DNS, the IP allowlist, the credentials, the permissions — and prints
the collection counts it found, so it also answers "am I looking at the right
database".

`migrate:db` copies the existing database to the new one, preserving `_id`s and
indexes, which means accounts, key bundles, message ciphertext and groups carry
over and tokens already issued to phones keep working. Run it with the old
server stopped, since it copies a snapshot. **Attachment bytes are not in the
database** — with `STORAGE_DRIVER=local` they are files under `server/var/media`
and with `s3` they are bucket objects; copy those yourself or existing
downloads will 404.

Two things worth knowing about the free tier: an M0 cluster is paused after 30
days without use and needs a click to wake, and it holds 512 MB, which is plenty
for ciphertext but not for attachments. Nothing about the design weakens: the
database still only ever sees ciphertext, because that is all the server has.

`server/.env` holds the database password and the JWT signing key. This project
keeps no key material there by design, but a sync client will happily copy that
file to every machine you own — keep the folder private, and use a long random
database password rather than one you reuse elsewhere.

On startup the server prints the addresses to type into the app:

```
  SecureChat is listening. Enter one of these in the app
  (Settings -> Server address):

    http://192.168.0.100:4000
    http://10.0.2.2:4000   (Android emulator)
```

Sign-in uses a **phone number and password**, not an SMS code. A number can be
registered exactly once; after that it is only ever used to sign in. See
[section 2.0](#20-accounts-one-number-one-password-registered-once).

`GET /health` reports the database state, which is what the app's connection
test calls.

### Verifying a LAN install

With the server running, exercise the whole path a user follows:

```bash
node tools/e2e-lan.mjs                       # uses the printed LAN address
node tools/e2e-lan.mjs http://10.0.2.2:4000  # or name it explicitly
```

It registers two accounts, performs an X3DH bundle fetch, exchanges ciphertext
in both directions, and asserts the zero-knowledge invariants still hold on a
live server: ciphertext returns byte-identical, no plaintext field appears
anywhere, a request carrying `plaintext` is rejected 400, and a third party gets
403 on the thread. It also covers the password rules: a number cannot be
registered twice (in any format), a wrong password is refused, a wrong password
is indistinguishable from an unknown account, and a weak password is rejected.

The last steps cover the two things that only break on a real LAN: an encrypted
attachment is presigned, uploaded, fetched back and decrypted, and the URL the
server hands out is checked to carry the same host the test is talking to —
which is what `PUBLIC_URL` gets wrong, showing up as chats that work and photos
that never load. The chat list is checked too, so a message that never appears
in the other person's list cannot pass silently.

To hand the APKs to phones:

```bash
node tools/serve-apk.cjs     # then open http://<lan-ip>:8080/ on the phone
```

The landing page lists every build with its size and which devices it suits.
It serves only files from `dist/`, so nothing else on disk is reachable.

### App

```bash
cd app
flutter test                  # crypto, protocol, discovery and address tests
flutter run
```

The server address is a **runtime** setting, not a compile-time constant, so
one APK works for everyone. A fresh install finds the server by itself: it
broadcasts a UDP datagram on port 41234 and the server answers with the address
to use, which is why nothing has to be typed on a phone sharing the Wi-Fi. If
that is blocked (some routers drop the broadcast), the address can still be
entered on the login screen or in Settings → Server address, and both places
offer a "Test connection" button. It is seeded from
`--dart-define=API_BASE_URL` if you want a preconfigured build.

| Where the app runs | What to enter |
|---|---|
| Android emulator | `http://10.0.2.2:4000` |
| Phone on the same Wi-Fi | `http://192.168.0.100:4000` (printed by the server) |
| Hosted server | `https://chat.example.com` |

### APK

```bash
flutter build apk --release
```

Produces a **universal** APK plus per-ABI splits:

```
dist/SecureChat-1.0.0.apk                 universal, runs on any device
dist/SecureChat-arm64-v8a-release.apk     ~40% smaller, most modern phones
dist/SecureChat-armeabi-v7a-release.apk   older 32-bit devices
dist/SecureChat-x86_64-release.apk        emulators
```

Ship the universal one for simplicity; ship the arm64 split if download size
matters. Anyone can install it: download the APK, allow "Install from unknown
sources" for the browser, and open it. No build-time configuration needed.

Releases are signed with `android/securechat-release.jks`, generated by
`tools/make-keystore.ps1`. Keep that file and `keystore.properties` together and
out of version control: Android identifies the app by its signing key, so losing
them means existing installs cannot be updated in place. If no keystore is
present the build falls back to the debug key so a fresh clone still compiles.

---

## 5. Security properties, and their limits

**Provided:**

- Private keys generated on-device, stored in the Android Keystore / iOS
  Keychain, never transmitted.
- X3DH with signature verification: a substituted signed pre-key is rejected
  (`test/crypto_test.dart`: "rejects a forged signed pre-key").
- Forward secrecy via a per-message ratchet, with skipped keys so
  out-of-order delivery still decrypts.
- Confidentiality and integrity of the header via GCM additional data.
- Identity pinning: a changed peer key is surfaced as a safety-number change
  rather than silently trusted.
- Zero-knowledge server, enforced by middleware, schema and socket guard.
- Pre-key atomicity: a one-time pre-key cannot service two handshakes.
- Screenshot prevention via `FLAG_SECURE` (prevention, not detection).
- Cloud backup and device transfer disabled, so keys are never cloned.
- Cleartext HTTP permitted only for emulator loopback; everything else must be
  HTTPS.

**Not provided. Be aware of these before deploying:**

- **No certificate pinning.** Add it before production; the current transport
  relies on the system trust store. Note that cleartext HTTP is permitted for
  user-configured servers, because a self-hoster picks the address at runtime
  and cannot be enumerated at build time. Message content stays end-to-end
  encrypted either way, so only metadata is exposed; the app shows a "no TLS"
  warning whenever the address is http://.
- **No push notifications.** A backgrounded app receives nothing until it
  reconnects, so FCM would be needed, carrying no message content.
- **Multi-device is partial.** One identity per install; there is no linked
  device list and no session transfer between devices.
- **No account recovery.** A forgotten password cannot be reset, because proving
  ownership of a number would need a channel this design does not have. Losing
  the phone loses the history too. Both are the intended trade-off, but they
  are real.
- **Password, not SMS verification.** Anyone who learns a number *and* its
  password can sign in. The number is an identifier here, not a second factor.
  The per-account lockout and per-IP rate limit bound online guessing, but a
  leaked password list would do more damage than it would under OTP.
- **Server-side metadata is visible.** The server knows who talks to whom and
  when. Message content is hidden; the graph is not. Hiding that needs a
  further layer such as sealed sender or mixnet routing.
- **Rate limits are per-IP and in-process.** A multi-instance deployment needs
  a shared store such as Redis.
- **Group UI is not wired up.** `GroupService`, the Sender Key chains, and the
  server's group routes are all complete and compile clean, but the chat screen
  still sends 1:1. Group compose needs connecting before groups are usable
  end to end.
- **BLE mesh is scaffolded, not finished.** `mesh/ble_mesh.dart` has scanning
  and frame chunking but no transport, so it is not part of the working app.
- **The offline mesh sends PLAINTEXT.** This is the most important limitation on
  this page. See §2.8.

---

## 6. What the tests actually check

The crypto tests use real handshakes, not mocks: two generated devices derive a
shared secret and exchange messages through the genuine code path.

```
17 passing
  X25519 curve mapping ... deterministic, matches the derived key
  identity keys ......... sign/verify round-trip, tamper and
                          wrong-key rejection
  X3DH .................. both sides derive the same secret; forged
                          pre-key refused
  ratchet ............... first message; full bidirectional exchange;
                          unique nonce and key per message; tampered
                          ciphertext and header rejected; out-of-order
                          delivery; state survives serialisation
```

The server tests assert the zero-knowledge invariants directly: a body with
`plaintext` is rejected 400, a nested `body` inside the header is rejected, a
private key on the key-upload route is rejected, and no `decrypt` endpoint
exists.
