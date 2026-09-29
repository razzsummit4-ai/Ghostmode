import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';

import 'package:securechat/crypto/keys.dart';
import 'package:securechat/crypto/kdf.dart';
import 'package:securechat/crypto/ratchet.dart';
import 'package:securechat/crypto/x3dh.dart';
import 'helpers/test_devices.dart';

/// A pair of live ratchet sessions established over a real X3DH handshake.
class _Pair {
  _Pair(this.aliceSession, this.bobSession);

  final RatchetSession aliceSession;
  final RatchetSession bobSession;
}

/// Run the full handshake and build both sides' ratchet sessions.
Future<_Pair> establishPair() async {
  final alice = await makeDevice();
  final bob = await makeDevice();

  // Alice initiates, consuming one of Bob's one-time pre-keys.
  final result = await X3dh.initiate(
    ourIdentity: alice.identity,
    theirBundle: bob.bundle('bob'),
  );

  // Bob responds using the same pre-key, and must reach the same secret.
  final bobSecret = await X3dh.respond(
    ourIdentity: bob.identity,
    ourSignedPreKeyPair: bob.signedPreKey,
    ourOneTimePreKeyPair: bob.oneTimePreKeys.first,
    theirIdentityKey: alice.identity.edPublic,
    theirEphemeralKey: result.ephemeralPublicKey,
  );
  expect(result.sharedSecret, equals(bobSecret));

  final aliceSession = await RatchetSession.fromSharedSecret(
    peerUserId: 'bob',
    sharedSecret: result.sharedSecret,
    localIdentityKey: alice.identity.edPublic,
    peerIdentityKey: bob.identity.edPublic,
    localBaseKeyPair: result.ephemeralKeyPair,
    peerBaseKey: result.ephemeralPublicKey,
    isInitiator: true,
  );

  // Bob has no ratchet key of his own yet; his first send generates one.
  final bobSession = await RatchetSession.fromSharedSecret(
    peerUserId: 'alice',
    sharedSecret: bobSecret,
    localIdentityKey: bob.identity.edPublic,
    peerIdentityKey: alice.identity.edPublic,
    localBaseKeyPair: null,
    peerBaseKey: result.ephemeralPublicKey,
    isInitiator: false,
  );

  return _Pair(aliceSession, bobSession);
}

/// Deliver one message, applying the ratchet exactly as the transport would.
Future<String> deliver(
  RatchetSession from,
  RatchetSession to, {
  String text = 'hello',
}) async {
  final msg = await from.encrypt(utf8.encode(text));
  to.notePeerRatchetKey(unb64(msg.header['ratchetKey'] as String));
  final opened = await to.decrypt(msg.ciphertext, msg.iv, msg.header);
  return utf8.decode(opened.plaintext);
}

void main() {
  test('the first message round-trips after a handshake', () async {
    final pair = await establishPair();
    expect(await deliver(pair.aliceSession, pair.bobSession, text: 'first'), 'first');
  });

  test('a full exchange works in both directions', () async {
    final pair = await establishPair();
    expect(await deliver(pair.aliceSession, pair.bobSession, text: 'ping'), 'ping');
    expect(await deliver(pair.bobSession, pair.aliceSession, text: 'pong'), 'pong');
    expect(await deliver(pair.aliceSession, pair.bobSession, text: 'ping2'), 'ping2');
    expect(await deliver(pair.bobSession, pair.aliceSession, text: 'pong2'), 'pong2');
  });

  test('each message uses a distinct nonce and key', () async {
    final pair = await establishPair();

    final first = await pair.aliceSession.encrypt(utf8.encode('same text'));
    final second = await pair.aliceSession.encrypt(utf8.encode('same text'));

    expect(first.iv, isNot(equals(second.iv)), reason: 'IV must be unique per message');
    expect(
      first.ciphertext,
      isNot(equals(second.ciphertext)),
      reason: 'identical plaintext must not yield identical ciphertext',
    );
  });

  test('a tampered ciphertext fails authentication', () async {
    final pair = await establishPair();
    final msg = await pair.aliceSession.encrypt(utf8.encode('sensitive'));
    pair.bobSession.notePeerRatchetKey(unb64(msg.header['ratchetKey'] as String));

    final tampered = Uint8List.fromList(msg.ciphertext);
    tampered[0] ^= 0xFF;

    await expectLater(
      pair.bobSession.decrypt(tampered, msg.iv, msg.header),
      throwsA(isA<ProtocolException>()),
    );
  });

  test('a tampered header fails authentication', () async {
    final pair = await establishPair();
    final msg = await pair.aliceSession.encrypt(utf8.encode('sensitive'));
    pair.bobSession.notePeerRatchetKey(unb64(msg.header['ratchetKey'] as String));

    // The header is bound in as AAD, so editing it must break decryption.
    final tamperedHeader = Map<String, dynamic>.from(msg.header);
    tamperedHeader['counter'] = 99;

    await expectLater(
      pair.bobSession.decrypt(msg.ciphertext, msg.iv, tamperedHeader),
      throwsA(isA<ProtocolException>()),
    );
  });

  test('out-of-order delivery still decrypts', () async {
    final pair = await establishPair();
    await deliver(pair.aliceSession, pair.bobSession, text: 'warmup');

    // Encrypt three messages, then deliver them out of order: 0, 2, 1.
    final m0 = await pair.aliceSession.encrypt(utf8.encode('zero'));
    final m1 = await pair.aliceSession.encrypt(utf8.encode('one'));
    final m2 = await pair.aliceSession.encrypt(utf8.encode('two'));

    final seen = <String>[];
    for (final m in [m0, m2, m1]) {
      pair.bobSession.notePeerRatchetKey(unb64(m.header['ratchetKey'] as String));
      final opened = await pair.bobSession.decrypt(m.ciphertext, m.iv, m.header);
      seen.add(utf8.decode(opened.plaintext));
    }

    // Each message decrypts to its own plaintext regardless of arrival order.
    expect(seen, equals(['zero', 'two', 'one']));
  });

  test('session state survives serialisation', () async {
    final pair = await establishPair();
    await deliver(pair.aliceSession, pair.bobSession, text: 'before restart');

    // Persist the sender to secure storage and reload it, as a cold start
    // would, then continue the conversation on the same chain.
    final encoded = jsonEncode(pair.aliceSession.toJson());
    final restored =
        RatchetSession.fromJson(jsonDecode(encoded) as Map<String, dynamic>);

    final msg = await restored.encrypt(utf8.encode('after restart'));
    pair.bobSession.notePeerRatchetKey(unb64(msg.header['ratchetKey'] as String));
    final opened = await pair.bobSession.decrypt(msg.ciphertext, msg.iv, msg.header);

    expect(utf8.decode(opened.plaintext), 'after restart');
  });
}
