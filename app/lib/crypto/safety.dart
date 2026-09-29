import 'dart:typed_data';

import 'package:crypto/crypto.dart' show sha512;

import 'keys.dart';

/// 60-digit safety number (12 groups of 5), Signal-style.
///
/// fingerprint = SHA-512(min(IK_A, IK_B) || max(IK_A, IK_B))[0..60 bytes]
/// rendered as 30 x uint16 mod 100000. Both sides sort identically so the
/// digits agree; a MITM substitution changes them visibly.
class SafetyNumbers {
  const SafetyNumbers._();

  static String compute(Uint8List localIk, Uint8List remoteIk) {
    final a = b64(localIk);
    final b = b64(remoteIk);
    final first = a.compareTo(b) <= 0 ? localIk : remoteIk;
    final second = identical(first, localIk) ? remoteIk : localIk;
    final digest = sha512.convert([...first, ...second]).bytes;
    final buf = StringBuffer();
    for (var i = 0; i < 30; i++) {
      final v = (digest[i * 2] << 8) | digest[i * 2 + 1];
      buf.write((v % 100000).toString().padLeft(5, '0'));
    }
    final all = buf.toString().substring(0, 60);
    return [for (var i = 0; i < 12; i++) all.substring(i * 5, i * 5 + 5)]
        .join(' ');
  }
}
