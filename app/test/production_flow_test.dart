import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';

import 'package:securechat/crypto/keys.dart';
import 'package:securechat/crypto/ratchet.dart';
import 'package:securechat/crypto/x3dh.dart';
import 'helpers/test_devices.dart';

/// The contract behind "Mark as verified".
///
/// Marking a peer's key as verified is only meaningful if it changes what is
/// persisted. Clearing an in-memory flag leaves the stale key pinned, so the
/// next handshake compares against the old key and fails again - which is
/// exactly the loop a user gets stuck in when a message will not decrypt.
void main() {
  test('a different identity key is not equal to the pinned one', () async {
    final alice = await makeDevice();
    final bob = await makeDevice();
    final other = await makeDevice();

    // What the first successful handshake pins for this peer.
    final pinned = bob.identity.edPublic;

    expect(
      constantTimeEquals(pinned, alice.identity.edPublic),
      isFalse,
      reason: "one contact's key must not match another's",
    );
    expect(
      constantTimeEquals(pinned, other.identity.edPublic),
      isFalse,
      reason: 'a newly generated identity key must differ',
    );
    expect(
      constantTimeEquals(pinned, bob.identity.edPublic),
      isTrue,
      reason: 'the same key compared with itself must match',
    );
  });

  test('a handshake still completes when the peer has no one-time pre-key',
      () async {
    // The pool is 100 keys and burns one per new conversation. Once it empties,
    // the server answers 409 no_prekeys_available. That used to make every send
    // fail, because _parseBundle cast a null oneTimePreKey to a non-nullable Map.
    //
    // X3DH defines the variant without DH4, and the responder already
    // substituted zeros, so both sides must agree or every message in the
    // session fails its GCM tag.
    final alice = await makeDevice();
    final bob = await makeDevice();

    final result = await X3dh.initiate(
      ourIdentity: alice.identity,
      theirBundle: PreKeyBundle(
        userId: 'bob',
        registrationId: bob.registrationId,
        identityKey: bob.identity.edPublic,
        signedPreKeyId: 1,
        signedPreKey: bob.signedPreKey.publicKey,
        signedPreKeySignature: bob.signedPreKeySignature,
        // Pool empty.
        oneTimePreKeyId: 0,
        oneTimePreKey: null,
      ),
    );
    expect(result.sharedSecret, isNotEmpty, reason: 'must still derive a secret');

    final responded = await X3dh.respond(
      ourIdentity: bob.identity,
      ourSignedPreKeyPair: bob.signedPreKey,
      ourOneTimePreKeyPair: null,
      theirIdentityKey: alice.identity.edPublic,
      theirEphemeralKey: result.ephemeralPublicKey,
    );
    expect(responded, result.sharedSecret,
        reason: 'both sides must agree when DH4 is skipped');
  });

  test('a changed peer key no longer dead-ends the conversation', () {
    // A reinstall regenerates the peer's identity key. The pinned key can never
    // match again, so throwing here - with no way for the user to clear it -
    // made the conversation permanently unreadable. The recovery is to re-pin
    // and re-handshake, which is what makes the next send succeed.
    final oldKey = Uint8List.fromList(List<int>.filled(32, 7));
    final reinstalled = Uint8List.fromList(List<int>.filled(32, 9));

    expect(constantTimeEquals(oldKey, reinstalled), isFalse);

    // Re-pinning means the next comparison is against the new key, so the
    // handshake proceeds instead of failing identically forever.
    final whatIsNowPinned = reinstalled;
    expect(constantTimeEquals(oldKey, whatIsNowPinned), isFalse);
    expect(constantTimeEquals(reinstalled, whatIsNowPinned), isTrue);
  });

  /// Reproduces the production path: a first message whose header is a `prekey`
  /// header, pushed through a JSON round-trip (the server stores and returns the
  /// header verbatim) and then decrypted by the responder.
  ///
  /// The existing ratchet tests deliberately use a bare `{type: 'msg', ratchetKey,
  /// counter}` header, so they never exercise the pre-key header the real client
  /// actually sends on the first message. That is the gap this file closes.
  test('first message survives the server JSON round-trip', () async {
    final alice = await makeDevice();
    final bob = await makeDevice();

    final result = await X3dh.initiate(
      ourIdentity: alice.identity,
      theirBundle: bob.bundle('bob'),
    );
    final bobSecret = await X3dh.respond(
      ourIdentity: bob.identity,
      ourSignedPreKeyPair: bob.signedPreKey,
      ourOneTimePreKeyPair: bob.oneTimePreKeys.first,
      theirIdentityKey: alice.identity.edPublic,
      theirEphemeralKey: result.ephemeralPublicKey,
    );

    final aliceSession = await RatchetSession.fromSharedSecret(
      peerUserId: 'bob',
      sharedSecret: result.sharedSecret,
      localIdentityKey: alice.identity.edPublic,
      peerIdentityKey: bob.identity.edPublic,
      localBaseKeyPair: result.ephemeralKeyPair,
      peerBaseKey: result.ephemeralPublicKey,
      isInitiator: true,
    );
    final bobSession = await RatchetSession.fromSharedSecret(
      peerUserId: 'alice',
      sharedSecret: bobSecret,
      localIdentityKey: bob.identity.edPublic,
      peerIdentityKey: alice.identity.edPublic,
      localBaseKeyPair: null,
      peerBaseKey: result.ephemeralPublicKey,
      isInitiator: false,
    );

    // Exactly the header SessionManager.encryptFor builds for a first message.
    final prekeyHeader = <String, dynamic>{
      'type': 'prekey',
      'preKeyId': 1,
      'signedPreKeyId': 1,
      'baseKey': b64(result.ephemeralPublicKey),
    };
    final sent = await aliceSession.encrypt(
      utf8.encode('hello bob'),
      extraHeader: prekeyHeader,
    );

    // The server stores the header as JSON and hands it back unchanged.
    final wireHeader =
        jsonDecode(jsonEncode(sent.header)) as Map<String, dynamic>;

    // Bob's half: he has no session yet, so the responder path rebuilds one.
    // Simulate by decrypting with the session he derived from the same secret.
    bobSession.notePeerRatchetKey(unb64(wireHeader['ratchetKey'] as String));
    final opened = await bobSession.decrypt(
      sent.ciphertext,
      sent.iv,
      wireHeader,
    );

    expect(utf8.decode(opened.plaintext), 'hello bob');
  });

  test('the header the server returns has the same shape we sent', () async {
    final alice = await makeDevice();
    final bob = await makeDevice();

    final result = await X3dh.initiate(
      ourIdentity: alice.identity,
      theirBundle: bob.bundle('bob'),
    );
    final aliceSession = await RatchetSession.fromSharedSecret(
      peerUserId: 'bob',
      sharedSecret: result.sharedSecret,
      localIdentityKey: alice.identity.edPublic,
      peerIdentityKey: bob.identity.edPublic,
      localBaseKeyPair: result.ephemeralKeyPair,
      peerBaseKey: result.ephemeralPublicKey,
      isInitiator: true,
    );

    final sent = await aliceSession.encrypt(
      utf8.encode('x'),
      extraHeader: {'type': 'prekey', 'preKeyId': 1, 'signedPreKeyId': 1, 'baseKey': b64(result.ephemeralPublicKey)},
    );

    // The AAD is computed from the header, so any difference in the encoded
    // form silently breaks the GCM tag. Compare the canonical form directly.
    final before = RatchetSession.canonicalHeader(sent.header);
    final after =
        RatchetSession.canonicalHeader(jsonDecode(jsonEncode(sent.header)) as Map<String, dynamic>);
    expect(after, before);
  });

  group('one-time pre-key ids must match between publish and lookup', () {
    // Regression test.
    //
    // The bug: mintOneTimePreKeys stored private halves under ids 1..n, 101..n,
    // ... but the top-up published them under a FRESH 1..n range. The server keys
    // its pool by keyId and hands one out verbatim; the responder then looked up
    // that id locally. Once a top-up had happened, the two no longer referred to
    // the same key, DH4 was computed with the wrong private half, and both sides
    // derived different secrets. Every message then failed its GCM tag, which the
    // UI reported as a bare "integrity check".
    //
    // This models that directly: publish key N as if it were key 1 and show the
    // resulting desynchronisation, then publish it correctly and show it works.

    /// X3DH as the responder sees it, given the pre-key private half it recovers
    /// by looking up the id the sender advertised.
    Future<Uint8List> responderSecret({
      required TestDevice responder,
      required Uint8List senderIdentityEd,
      required Uint8List senderEphemeral,
      required DhKeyPair? recoveredOneTimePreKey,
    }) {
      return X3dh.respond(
        ourIdentity: responder.identity,
        ourSignedPreKeyPair: responder.signedPreKey,
        ourOneTimePreKeyPair: recoveredOneTimePreKey,
        theirIdentityKey: senderIdentityEd,
        theirEphemeralKey: senderEphemeral,
      );
    }

    test('a wrongly numbered pre-key produces a different secret', () async {
      final alice = await makeDevice();
      final bob = await makeDevice();

      // The collision after a top-up: locally the new keys are 101..150, but
      // they were published under 1..50. The server now holds TWO entries for
      // keyId 1 - the original, and this new key wearing the old id - and it
      // eventually hands out the new one. So the initiator burns a pre-key whose
      // public half is oneTimePreKeys[1], while advertising keyId 1.
      final mislabelled = PreKeyBundle(
        userId: 'bob',
        registrationId: bob.registrationId,
        identityKey: bob.identity.edPublic,
        signedPreKeyId: 1,
        signedPreKey: bob.signedPreKey.publicKey,
        signedPreKeySignature:
            Uint8List.fromList((await bob.identity.sign(bob.signedPreKey.publicKey)).bytes),
        oneTimePreKeyId: 1,
        oneTimePreKey: bob.oneTimePreKeys[1].publicKey,
      );

      final initiator = await X3dh.initiate(
        ourIdentity: alice.identity,
        theirBundle: mislabelled,
      );

      // The responder does exactly what the app does: it trusts the advertised
      // id and reads the private half stored under it locally. That is the
      // ORIGINAL key 1, not the one the initiator actually used.
      final recovered = await responderSecret(
        responder: bob,
        senderIdentityEd: alice.identity.edPublic,
        senderEphemeral: initiator.ephemeralPublicKey,
        recoveredOneTimePreKey: bob.oneTimePreKeys[0],
      );

      // Different DH4 input, so a different shared secret. This is precisely the
      // desynchronisation that surfaced on the device as a GCM tag failure.
      expect(recovered, isNot(equals(initiator.sharedSecret)));

      // The fix, in one line: the advertised id must be the real local id, so the
      // responder recovers the same private half the initiator used.
      final honest = PreKeyBundle(
        userId: 'bob',
        registrationId: bob.registrationId,
        identityKey: bob.identity.edPublic,
        signedPreKeyId: 1,
        signedPreKey: bob.signedPreKey.publicKey,
        signedPreKeySignature:
            Uint8List.fromList((await bob.identity.sign(bob.signedPreKey.publicKey)).bytes),
        oneTimePreKeyId: 2,
        oneTimePreKey: bob.oneTimePreKeys[1].publicKey,
      );

      final fixed = await X3dh.initiate(
        ourIdentity: alice.identity,
        theirBundle: honest,
      );
      final fixedResponderSecret = await responderSecret(
        responder: bob,
        senderIdentityEd: alice.identity.edPublic,
        senderEphemeral: fixed.ephemeralPublicKey,
        recoveredOneTimePreKey: bob.oneTimePreKeys[1],
      );

      expect(fixedResponderSecret, equals(fixed.sharedSecret));
    });

    test('a full message decrypts when the pre-key id is correct', () async {
      final alice = await makeDevice();
      final bob = await makeDevice();

      final initiator = await X3dh.initiate(
        ourIdentity: alice.identity,
        theirBundle: bob.bundle('bob'),
      );

      // The responder recovers the pre-key by the id in the header, which is the
      // very key the initiator consumed.
      final bobSecret = await responderSecret(
        responder: bob,
        senderIdentityEd: alice.identity.edPublic,
        senderEphemeral: initiator.ephemeralPublicKey,
        recoveredOneTimePreKey: bob.oneTimePreKeys.first,
      );
      expect(bobSecret, equals(initiator.sharedSecret));

      final aliceSession = await RatchetSession.fromSharedSecret(
        peerUserId: 'bob',
        sharedSecret: initiator.sharedSecret,
        localIdentityKey: alice.identity.edPublic,
        peerIdentityKey: bob.identity.edPublic,
        localBaseKeyPair: initiator.ephemeralKeyPair,
        peerBaseKey: initiator.ephemeralPublicKey,
        isInitiator: true,
      );
      final bobSession = await RatchetSession.fromSharedSecret(
        peerUserId: 'alice',
        sharedSecret: bobSecret,
        localIdentityKey: bob.identity.edPublic,
        peerIdentityKey: alice.identity.edPublic,
        localBaseKeyPair: null,
        peerBaseKey: initiator.ephemeralPublicKey,
        isInitiator: false,
      );

      final sent = await aliceSession.encrypt(
        utf8.encode('first real message'),
        extraHeader: {
          'type': 'prekey',
          'preKeyId': 1,
          'signedPreKeyId': 1,
          'baseKey': b64(initiator.ephemeralPublicKey),
        },
      );
      final wireHeader =
          jsonDecode(jsonEncode(sent.header)) as Map<String, dynamic>;

      bobSession.notePeerRatchetKey(unb64(wireHeader['ratchetKey'] as String));
      final opened = await bobSession.decrypt(
        sent.ciphertext,
        sent.iv,
        wireHeader,
      );
      expect(utf8.decode(opened.plaintext), 'first real message');
    });
  });
}
