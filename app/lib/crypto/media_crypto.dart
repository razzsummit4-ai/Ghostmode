import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'keys.dart';

/// Encrypt-then-upload pipeline for attachments.
///
/// The order is what makes media safe:
///  1. a random 256-bit file key and 12-byte IV are generated here;
///  2. the file is sealed with AES-256-GCM on this device;
///  3. only the ciphertext is uploaded;
///  4. the file key travels inside the message body, which is itself already
///     encrypted by the Double Ratchet.
///
/// So the storage backend holds bytes it cannot read, and the key that could
/// read them exists only inside an E2E session.
class MediaCrypto {
  const MediaCrypto._();

  /// Seal [plain]. Returns the uploadable blob plus the key envelope that will
  /// be embedded in the (separately encrypted) message body.
  static Future<({Uint8List blob, Map<String, dynamic> keyEnvelope})> encrypt(
    Uint8List plain,
    String fileName,
    String mime,
  ) async {
    final key = secureRandomBytes(32);
    try {
      final sealed = await aesGcm256.encrypt(
        plain,
        secretKey: SecretKey(key),
        nonce: secureRandomBytes(12),
      );
      final blob =
          Uint8List.fromList([...sealed.cipherText, ...sealed.mac.bytes]);
      return (
        blob: blob,
        keyEnvelope: {
          'fileKey': b64(key),
          'fileIv': b64(Uint8List.fromList(sealed.nonce)),
          'fileName': fileName,
          'mime': mime,
          'size': plain.length,
          'sha256': b64(await sha256Bytes(plain)),
        },
      );
    } finally {
      wipe(key);
    }
  }

  /// Open a downloaded blob using the key envelope from the message.
  static Future<Uint8List> decrypt(
    Uint8List blob,
    Map<String, dynamic> envelope,
  ) async {
    final key = unb64('${envelope['fileKey']}');
    final iv = unb64('${envelope['fileIv']}');
    try {
      const tagLen = 16;
      if (blob.length < tagLen) {
        throw const FormatException('Attachment is truncated.');
      }
      return Uint8List.fromList(
        await aesGcm256.decrypt(
          SecretBox(
            blob.sublist(0, blob.length - tagLen),
            nonce: iv,
            mac: Mac(blob.sublist(blob.length - tagLen)),
          ),
          secretKey: SecretKey(key),
        ),
      );
    } on SecretBoxAuthenticationError {
      // The blob was altered in transit or at rest.
      throw const FormatException('Attachment failed its integrity check.');
    } finally {
      wipe(key);
    }
  }

  /// Integrity digest of the plaintext, so a corrupted download is detectable
  /// independently of the GCM tag.
  static Future<Uint8List> sha256Bytes(Uint8List bytes) async =>
      Uint8List.fromList((await Sha256().hash(bytes)).bytes);
}
