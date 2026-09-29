import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:crypto/crypto.dart' as crypto;

/// Cryptographically secure random bytes.
///
/// `Random.secure()` is backed by the platform CSPRNG (OpenSSL/BoringSSL on
/// Android, Security.framework on iOS). Never substitute `Random()`: it is a
/// deterministic PRNG and would void every guarantee in this codebase.
Uint8List secureRandomBytes(int length) {
  final rng = Random.secure();
  final out = Uint8List(length);
  for (var i = 0; i < length; i++) {
    out[i] = rng.nextInt(256);
  }
  return out;
}

/// Constant-time comparison, to avoid leaking key material via timing.
bool constantTimeEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

/// Overwrite a buffer in place. Used to drop key material after use.
void wipe(List<int> buffer) {
  for (var i = 0; i < buffer.length; i++) {
    buffer[i] = 0;
  }
}

String b64(List<int> bytes) => base64Encode(bytes);
Uint8List unb64(String value) => Uint8List.fromList(base64Decode(value));

/// Shared algorithm instances, so platform-backed implementations are reused.
final Ed25519 ed25519 = Ed25519();
final X25519 x25519 = X25519();
final AesGcm aesGcm256 = AesGcm.with256bits();

/// An X25519 key pair: every Diffie-Hellman operation in the protocol uses one.
class DhKeyPair {
  DhKeyPair._(this._publicKey, this._privateKey);

  final Uint8List _publicKey;
  final Uint8List _privateKey;

  /// Public half. Safe to publish to the server.
  Uint8List get publicKey => Uint8List.fromList(_publicKey);
  String get publicBase64 => b64(_publicKey);

  /// Private half. Never leaves the device and is never sent over the network.
  Uint8List get privateKey => Uint8List.fromList(_privateKey);
  String get privateBase64 => b64(_privateKey);

  /// Generate a fresh ephemeral, signed pre-key, or one-time pre-key.
  static Future<DhKeyPair> generate() async {
    final kp = await x25519.newKeyPairFromSeed(secureRandomBytes(32));
    return DhKeyPair._(
      Uint8List.fromList((await kp.extractPublicKey()).bytes),
      Uint8List.fromList(await kp.extractPrivateKeyBytes()),
    );
  }

  /// Reconstruct from persisted state. Both halves are stored, so this is exact.
  static DhKeyPair fromStored({
    required List<int> publicKey,
    required List<int> privateKey,
  }) => DhKeyPair._(Uint8List.fromList(publicKey), Uint8List.fromList(privateKey));

  /// The `cryptography` key-pair view used for Diffie-Hellman.
  ///
  /// X25519 scalar multiplication needs the public key bound to the private
  /// half, so both are supplied together.
  KeyPair get keyPair => SimpleKeyPairData(
        _privateKey,
        publicKey: SimplePublicKey(_publicKey, type: KeyPairType.x25519),
        type: KeyPairType.x25519,
      );

  /// Reconstruct a public-only handle (no private material present).
  static DhKeyPair publicOnly(List<int> publicKey) =>
      DhKeyPair._(Uint8List.fromList(publicKey), Uint8List(32));

  @override
  String toString() => 'DhKeyPair(pub=${b64(_publicKey).substring(0, 8)}…)';
}

/// An Ed25519 signature (64 bytes) together with the public key that made it.
typedef EdSignature = Signature;

/// The device's long-lived identity key pair: the root of trust.
///
/// The Ed25519 key signs the signed pre-key; the matching Curve25519 key does
/// Diffie-Hellman. The PRIVATE seed is generated on-device, stored only in the
/// platform Keystore/Keychain, and never serialised into a network request.
/// Only [publicBase64] is ever uploaded.
class IdentityKeyPair {
  IdentityKeyPair._({
    required this.edPublic,
    required this.edPrivate,
    required this.xPublic,
    required this.xPrivate,
  });

  /// Ed25519 public key (32 bytes). This is what the server stores.
  final Uint8List edPublic;

  /// Ed25519 private seed (32 bytes). Secure storage only.
  final Uint8List edPrivate;

  /// Curve25519 public key derived from the identity, used for ECDH.
  final Uint8List xPublic;

  /// Curve25519 private scalar derived from the identity.
  final Uint8List xPrivate;

  String get publicBase64 => b64(edPublic);
  Uint8List get publicKey => Uint8List.fromList(edPublic);
  Uint8List get privateKey => Uint8List.fromList(edPrivate);

  /// Generate a brand-new identity for this device.
  static Future<IdentityKeyPair> generate() => fromSeed(secureRandomBytes(32));

  /// Rebuild from a stored Ed25519 seed.
  ///
  /// The Curve25519 halves are always re-derived from the seed rather than
  /// loaded from disk, so the two can never drift out of sync.
  static Future<IdentityKeyPair> fromSeed(List<int> seed) async {
    final ed = await ed25519.newKeyPairFromSeed(Uint8List.fromList(seed));
    final edPub = Uint8List.fromList((await ed.extractPublicKey()).bytes);
    final edPriv = Uint8List.fromList(await ed.extractPrivateKeyBytes());

    // Montgomery scalar = clamp(SHA-512(seed)[0..32]).
    final scalar = Uint8List.fromList(
      crypto.sha512.convert(edPriv).bytes.sublist(0, 32),
    );
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    // The X25519 public key is the scalar times the curve base point; deriving
    // it through the audited key-pair API keeps us off hand-rolled curve maths.
    final xPair = await x25519.newKeyPairFromSeed(scalar);
    final xPub = Uint8List.fromList((await xPair.extractPublicKey()).bytes);
    final xPriv = Uint8List.fromList(await xPair.extractPrivateKeyBytes());

    return IdentityKeyPair._(
      edPublic: edPub,
      edPrivate: edPriv,
      xPublic: xPub,
      xPrivate: xPriv,
    );
  }

  /// The Curve25519 key pair derived from this identity, for DH.
  DhKeyPair get dhKeyPair => DhKeyPair._(xPublic, xPrivate);

  /// Sign arbitrary bytes with the Ed25519 private key.
  ///
  /// The returned [Signature] carries the signing public key, which the X3DH
  /// layer ignores in favour of the peer's pinned identity key.
  Future<Signature> sign(List<int> message) {
    return ed25519.sign(
      message,
      keyPair: SimpleKeyPairData(
        edPrivate,
        publicKey: SimplePublicKey(edPublic, type: KeyPairType.ed25519),
        type: KeyPairType.ed25519,
      ),
    );
  }

  /// Verify an Ed25519 signature against an identity public key.
  ///
  /// The `cryptography` package binds the verifying key onto the [Signature],
  /// so we attach the expected identity key before verifying. A mismatch
  /// therefore fails, which is exactly the property we need.
  static Future<bool> verify({
    required List<int> signature,
    required List<int> message,
    required List<int> publicKeyBytes,
  }) async {
    try {
      return await ed25519.verify(
        message,
        signature: Signature(
          Uint8List.fromList(signature),
          publicKey: SimplePublicKey(
            Uint8List.fromList(publicKeyBytes),
            type: KeyPairType.ed25519,
          ),
        ),
      );
    } catch (_) {
      // A malformed signature is a verification failure, not a crash.
      return false;
    }
  }

  @override
  String toString() => 'IdentityKeyPair(pub=${b64(edPublic).substring(0, 8)}…)';
}
