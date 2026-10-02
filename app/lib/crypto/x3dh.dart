import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'curve.dart';
import 'kdf.dart';
import 'keys.dart';

/// Public half of a peer's identity, as fetched from the server.
class RemoteIdentity {
  RemoteIdentity({
    required this.userId,
    required this.registrationId,
    required this.edPublicKey,
  });

  final String userId;
  final int registrationId;
  final Uint8List edPublicKey;
}

/// Everything a sender needs to start an X3DH session with a peer.
class PreKeyBundle {
  PreKeyBundle({
    required this.userId,
    required this.registrationId,
    required this.identityKey,
    required this.signedPreKeyId,
    required this.signedPreKey,
    required this.signedPreKeySignature,
    required this.oneTimePreKeyId,
    required this.oneTimePreKey,
  });

  final String userId;
  final int registrationId;
  final Uint8List identityKey;
  final int signedPreKeyId;
  final Uint8List signedPreKey;
  final Uint8List signedPreKeySignature;

  /// Null when the peer's one-time pre-key pool is empty. The handshake then
  /// omits the DH4 term, which both sides treat as zeros.
  final Uint8List? oneTimePreKey;

  /// 0 when there is no [oneTimePreKey]. The responder reads that as "the
  /// sender skipped DH4" rather than "pre-key id zero".
  final int oneTimePreKeyId;

  Map<String, dynamic> toJson() => {
    'userId': userId,
    'registrationId': registrationId,
    'identityKey': b64(identityKey),
    'signedPreKeyId': signedPreKeyId,
    'signedPreKey': b64(signedPreKey),
    'signedPreKeySignature': b64(signedPreKeySignature),
    'oneTimePreKeyId': oneTimePreKeyId,
    'oneTimePreKey': oneTimePreKey == null ? null : b64(oneTimePreKey!),
  };

  static PreKeyBundle fromJson(Map<String, dynamic> json) => PreKeyBundle(
    userId: json['userId'] as String,
    registrationId: (json['registrationId'] as num).toInt(),
    identityKey: unb64(json['identityKey'] as String),
    signedPreKeyId: (json['signedPreKeyId'] as num).toInt(),
    signedPreKey: unb64(json['signedPreKey'] as String),
    signedPreKeySignature: unb64(json['signedPreKeySignature'] as String),
    oneTimePreKeyId: (json['oneTimePreKeyId'] as num).toInt(),
    oneTimePreKey: json['oneTimePreKey'] == null
        ? null
        : unb64(json['oneTimePreKey'] as String),
  );
}

/// Result of an X3DH handshake, fed straight into a RatchetSession.
class X3dhResult {
  const X3dhResult({
    required this.sharedSecret,
    required this.associatedData,
    required this.ephemeralPublicKey,
    required this.ephemeralKeyPair,
  });

  final Uint8List sharedSecret;

  /// Both identity keys, mixed in so the session is bound to these peers.
  final Uint8List associatedData;

  /// Our ephemeral public key, sent as the message header's base key.
  final Uint8List ephemeralPublicKey;

  /// The full ephemeral key pair.
  ///
  /// The initiator keeps this as its first ratchet key pair, which is exactly
  /// what the Signal specification calls the "base key". Discarding the private
  /// half here would leave the initiator unable to perform its first DH
  /// ratchet step, so it is retained on-device and never transmitted.
  final DhKeyPair ephemeralKeyPair;
}

/// Extended Triple Diffie-Hellman (X3DH), per the Signal specification.
///
/// Establishes a shared secret between two devices that have never spoken,
/// giving the initiator forward secrecy and authenticating the responder's
/// long-term identity.
class X3dh {
  const X3dh._();

  /// Initiator side: verify the bundle, generate an ephemeral key, derive SK.
  ///
  /// DH1 = DH(IK_A, SPK_B)   authenticates the responder
  /// DH2 = DH(EK_A, IK_B)   authenticates us
  /// DH3 = DH(EK_A, SPK_B)  contributes the ephemeral
  /// DH4 = DH(EK_A, OPK_B)  contributes a single-use pre-key
  static Future<X3dhResult> initiate({
    required IdentityKeyPair ourIdentity,
    required PreKeyBundle theirBundle,
  }) async {
    // Reject a signed pre-key the peer's identity key did not sign. Without
    // this an active attacker could substitute their own SPK.
    final signatureValid = await IdentityKeyPair.verify(
      signature: theirBundle.signedPreKeySignature,
      message: theirBundle.signedPreKey,
      publicKeyBytes: theirBundle.identityKey,
    );
    if (!signatureValid) {
      throw ProtocolException(
        'invalid_signed_prekey',
        'The peer signed pre-key signature did not verify.',
      );
    }

    final theirIkX = x25519FromEd25519(theirBundle.identityKey);
    final ephemeral = await DhKeyPair.generate();

    final dh1 = await _dh(ourIdentity.dhKeyPair, theirBundle.signedPreKey);
    final dh2 = await _dh(ephemeral, theirIkX);
    final dh3 = await _dh(ephemeral, theirBundle.signedPreKey);
    // No one-time pre-key means the sender skipped DH4. Zeros keep the
    // concatenation length fixed, matching what the responder does when it
    // finds no pre-key for the advertised id. Without this the initiator threw
    // and could not start a conversation with a device whose pool had run out.
    final dh4 = theirBundle.oneTimePreKey == null
        ? Uint8List(32)
        : await _dh(ephemeral, theirBundle.oneTimePreKey!);

    // Concatenate in the order the spec mandates, then bind to both identity
    // keys so neither end can be substituted by a man in the middle.
    final concatenated = Uint8List.fromList([...dh1, ...dh2, ...dh3, ...dh4]);
    wipe(dh1);
    wipe(dh2);
    wipe(dh3);
    wipe(dh4);

    final sharedSecret = await Kdf.hkdf(
      concatenated,
      info: 'SecureChat/X3DH/v1',
      salt: Kdf.ones,
    );
    wipe(concatenated);

    final associatedData = Uint8List.fromList([
      ...ourIdentity.edPublic,
      ...theirBundle.identityKey,
    ]);

    return X3dhResult(
      sharedSecret: sharedSecret,
      associatedData: associatedData,
      ephemeralPublicKey: ephemeral.publicKey,
      // Retained as the initiator's first ratchet key pair (the X3DH base key).
      ephemeralKeyPair: ephemeral,
    );
  }

  /// Responder side: recompute the same secret from an incoming header.
  static Future<Uint8List> respond({
    required IdentityKeyPair ourIdentity,
    required DhKeyPair ourSignedPreKeyPair,
    required DhKeyPair? ourOneTimePreKeyPair,
    required Uint8List theirIdentityKey,
    required Uint8List theirEphemeralKey,
  }) async {
    final theirIkX = x25519FromEd25519(theirIdentityKey);
    final theirEphemeral = DhKeyPair.publicOnly(theirEphemeralKey);

    final dh1 = await _dh(ourSignedPreKeyPair, theirIkX);
    final dh2 = await _dh(ourIdentity.dhKeyPair, theirEphemeral.publicKey);
    final dh3 = await _dh(ourSignedPreKeyPair, theirEphemeral.publicKey);
    // No one-time pre-key on this side means the sender skipped DH4, so it
    // contributes zeros to keep the concatenation length fixed.
    final dh4 = ourOneTimePreKeyPair == null
        ? Uint8List(32)
        : await _dh(ourOneTimePreKeyPair, theirEphemeral.publicKey);

    final concatenated = Uint8List.fromList([...dh1, ...dh2, ...dh3, ...dh4]);
    wipe(dh1);
    wipe(dh2);
    wipe(dh3);
    wipe(dh4);

    final sharedSecret = await Kdf.hkdf(
      concatenated,
      info: 'SecureChat/X3DH/v1',
      salt: Kdf.ones,
    );
    wipe(concatenated);
    return sharedSecret;
  }

  /// Raw X25519 Diffie-Hellman.
  static Future<Uint8List> _dh(DhKeyPair ours, List<int> theirPublic) async {
    final secret = await x25519.sharedSecretKey(
      keyPair: ours.keyPair,
      remotePublicKey: SimplePublicKey(
        Uint8List.fromList(theirPublic),
        type: KeyPairType.x25519,
      ),
    );
    final bytes = Uint8List.fromList(await secret.extractBytes());

    // An all-zero output means the peer supplied a low-order point, which
    // would collapse the DH result to a predictable value. Fail closed.
    var nonZero = false;
    for (final b in bytes) {
      if (b != 0) {
        nonZero = true;
        break;
      }
    }
    if (!nonZero) {
      throw ProtocolException('invalid_dh_result', 'Degenerate Diffie-Hellman result.');
    }
    return bytes;
  }
}

/// Map a remote peer's Ed25519 identity key to its X25519 form for DH.
Uint8List x25519FromEd25519(Uint8List edPublic) {
  final mapped = Ed25519ToX25519.publicKey(edPublic);
  if (mapped == null) {
    throw ProtocolException('invalid_identity_key', 'Peer identity key is not mappable.');
  }
  return mapped;
}
