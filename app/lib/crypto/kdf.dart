import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// Shared HMAC instance, the primitive behind every chain-key step.
final Hmac hmacSha256 = Hmac.sha256();

/// Thrown when a message fails authentication, arrives out of order, or a
/// ratchet step cannot be completed. Never carries plaintext.
class ProtocolException implements Exception {
  ProtocolException(this.code, [this.detail]);

  final String code;
  final String? detail;

  @override
  String toString() => 'ProtocolException($code${detail == null ? '' : ': $detail'})';
}

/// Key derivation and authentication helpers shared by X3DH, the Double
/// Ratchet and the group Sender Key.
class Kdf {
  const Kdf._();

  /// HKDF-SHA256 with a mandatory context string.
  ///
  /// Every derived secret in this app is separated by a distinct `info` label,
  /// so a key derived for one purpose can never be reused for another. The
  /// label is XOR-ed into the salt, which binds the derived key to its purpose
  /// while keeping the input key material fully absorbed.
  static Future<Uint8List> hkdf(
    Uint8List inputKeyMaterial, {
    required String info,
    Uint8List? salt,
    int length = 32,
  }) async {
    final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: length);

    // Bind the purpose: salt' = salt XOR context (padded/truncated to 32 bytes).
    final context = utf8.encode(info);
    final effectiveSalt = Uint8List(32);
    final base = salt ?? effectiveSalt;
    for (var i = 0; i < 32; i++) {
      effectiveSalt[i] = (i < base.length ? base[i] : 0) ^ (i < context.length ? context[i] : 0);
    }

    final secret = await hkdf.deriveKey(
      secretKey: SecretKey(inputKeyMaterial),
      nonce: effectiveSalt,
    );
    return Uint8List.fromList(await secret.extractBytes());
  }

  /// HMAC-SHA256, the primitive behind every chain-key step in the ratchet.
  static Future<Uint8List> hmac(Uint8List key, Uint8List data) async {
    final mac = await hmacSha256.calculateMac(data, secretKey: SecretKey(key));
    return Uint8List.fromList(mac.bytes);
  }

  /// One 0x01 step: derive this message's key from the chain key.
  static Future<Uint8List> deriveMessageKey(Uint8List chainKey) =>
      hmac(chainKey, Uint8List.fromList([0x01]));

  /// Advance a chain key.
  ///
  /// The same constant is used on both sides: a sending chain on one device is
  /// the peer's receiving chain, so the two must step identically. Direction is
  /// expressed by *which* chain is in use, not by the constant.
  static Future<Uint8List> deriveNextChainKey(Uint8List chainKey) =>
      hmac(chainKey, Uint8List.fromList([0x02]));

  /// Constant "one" used as the HKDF salt, so the input key material is fully
  /// absorbed even when the two sides contribute different amounts of entropy.
  static Uint8List get ones => Uint8List(32)..fillRange(0, 32, 1);
}
