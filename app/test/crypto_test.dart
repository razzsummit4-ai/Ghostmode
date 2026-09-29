import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';

import 'package:securechat/crypto/curve.dart';
import 'package:securechat/crypto/keys.dart';
import 'package:securechat/crypto/kdf.dart';
import 'package:securechat/crypto/x3dh.dart';

/// A device identity plus its published pre-key bundle.
class _Device {
  _Device(this.identity, this.signedPreKey, this.oneTimePreKeys);

  final IdentityKeyPair identity;
  final DhKeyPair signedPreKey;
  final List<DhKeyPair> oneTimePreKeys;
  final int registrationId = 1;

  late Uint8List _signedPreKeySignature;

  /// The public bundle exactly as it would be uploaded to the server.
  PreKeyBundle bundle(String userId) => PreKeyBundle(
    userId: userId,
    registrationId: registrationId,
    identityKey: identity.edPublic,
    signedPreKeyId: 1,
    signedPreKey: signedPreKey.publicKey,
    signedPreKeySignature: _signedPreKeySignature,
    oneTimePreKeyId: 1,
    oneTimePreKey: oneTimePreKeys.first.publicKey,
  );
}

/// Build a device whose signed pre-key is signed by its own identity key.
Future<_Device> makeDevice() async {
  final identity = await IdentityKeyPair.generate();
  final signedPreKey = await DhKeyPair.generate();
  final oneTimePreKeys = [await DhKeyPair.generate(), await DhKeyPair.generate()];

  final device = _Device(identity, signedPreKey, oneTimePreKeys);
  device._signedPreKeySignature =
      Uint8List.fromList((await identity.sign(signedPreKey.publicKey)).bytes);
  return device;
}

void main() {
  group('X25519 curve mapping', () {
    test('rejects a key that is not mappable', () {
      // y == 1 (mod p) has no Montgomery form.
      final invalid = Uint8List(32);
      invalid[0] = 1;
      expect(Ed25519ToX25519.publicKey(invalid), isNull);
    });

    test('maps a real identity key deterministically', () async {
      final id = await IdentityKeyPair.generate();
      final a = Ed25519ToX25519.publicKey(id.edPublic);
      final b = Ed25519ToX25519.publicKey(id.edPublic);
      expect(a, isNotNull);
      expect(a, equals(b), reason: 'mapping must be deterministic');
      expect(a!.length, 32);
    });

    test('the mapped key equals the one derived from the seed', () async {
      // Cross-check that the RFC 7748 map agrees with the Montgomery scalar
      // we derive locally for our own identity.
      final id = await IdentityKeyPair.generate();
      expect(Ed25519ToX25519.publicKey(id.edPublic), equals(id.xPublic));
    });
  });

  group('identity keys', () {
    test('sign and verify round-trips', () async {
      final id = await IdentityKeyPair.generate();
      final message = utf8.encode('signed pre-key material');
      final sig = await id.sign(message);

      expect(
        await IdentityKeyPair.verify(
          signature: sig.bytes,
          message: message,
          publicKeyBytes: id.edPublic,
        ),
        isTrue,
      );
    });

    test('a tampered message fails verification', () async {
      final id = await IdentityKeyPair.generate();
      final sig = await id.sign(utf8.encode('original'));
      expect(
        await IdentityKeyPair.verify(
          signature: sig.bytes,
          message: utf8.encode('tampered'),
          publicKeyBytes: id.edPublic,
        ),
        isFalse,
      );
    });

    test('a different identity key fails verification', () async {
      final a = await IdentityKeyPair.generate();
      final b = await IdentityKeyPair.generate();
      final sig = await a.sign(utf8.encode('hello'));
      expect(
        await IdentityKeyPair.verify(
          signature: sig.bytes,
          message: utf8.encode('hello'),
          publicKeyBytes: b.edPublic,
        ),
        isFalse,
      );
    });

    test('regenerating from the same seed gives the same identity', () async {
      final id = await IdentityKeyPair.generate();
      final again = await IdentityKeyPair.fromSeed(id.privateKey);
      expect(again.edPublic, equals(id.edPublic));
      expect(again.xPublic, equals(id.xPublic));
    });
  });

  group('X3DH', () {
    test('initiator and responder derive the same shared secret', () async {
      final alice = await makeDevice();
      final bob = await makeDevice();

      final result = await X3dh.initiate(
        ourIdentity: alice.identity,
        theirBundle: bob.bundle('bob'),
      );

      final responder = await X3dh.respond(
        ourIdentity: bob.identity,
        ourSignedPreKeyPair: bob.signedPreKey,
        ourOneTimePreKeyPair: bob.oneTimePreKeys.first,
        theirIdentityKey: alice.identity.edPublic,
        theirEphemeralKey: result.ephemeralPublicKey,
      );

      expect(result.sharedSecret, equals(responder));
    });

    test('rejects a forged signed pre-key', () async {
      final alice = await makeDevice();
      final bob = await makeDevice();
      final eve = await makeDevice();

      // Eve substitutes her own signed pre-key but signs it with her identity,
      // so the signature will not verify against Bob's pinned identity key.
      final evilPreKey = await DhKeyPair.generate();
      final evilSig = await eve.identity.sign(evilPreKey.publicKey);

      await expectLater(
        X3dh.initiate(
          ourIdentity: alice.identity,
          theirBundle: PreKeyBundle(
            userId: bob.bundle('bob').userId,
            registrationId: 1,
            identityKey: bob.identity.edPublic,
            signedPreKeyId: 1,
            signedPreKey: evilPreKey.publicKey,
            signedPreKeySignature: Uint8List.fromList(evilSig.bytes),
            oneTimePreKeyId: 1,
            oneTimePreKey: bob.oneTimePreKeys.first.publicKey,
          ),
        ),
        throwsA(isA<ProtocolException>()),
      );
    });

    test('different peers produce different shared secrets', () async {
      final alice = await makeDevice();
      final bob = await makeDevice();
      final carol = await makeDevice();

      final toBob = await X3dh.initiate(
        ourIdentity: alice.identity,
        theirBundle: bob.bundle('bob'),
      );
      final toCarol = await X3dh.initiate(
        ourIdentity: alice.identity,
        theirBundle: carol.bundle('carol'),
      );

      expect(toBob.sharedSecret, isNot(equals(toCarol.sharedSecret)));
    });
  });
}
