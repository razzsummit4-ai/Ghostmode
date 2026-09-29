import 'dart:typed_data';

/// Ed25519 -> X25519 public key conversion (RFC 7748 §6.1, "edwards25519" map).
///
/// This is a published algebraic transform, not a hand-rolled primitive:
///
///     u = (1 + y) / (1 - y)   (mod p),   p = 2^255 - 19
///
/// The only non-trivial step is a modular inverse, which we delegate to
/// [BigInt.modInverse] (a general-purpose integer routine) rather than writing
/// field arithmetic by hand. `test/crypto_test.dart` checks this against
/// published RFC 7748 vectors and against Node's OpenSSL.
class Ed25519ToX25519 {
  const Ed25519ToX25519._();

  /// The field prime, 2^255 - 19.
  static final BigInt p = (BigInt.one << 255) - BigInt.from(19);

  /// Field element 1, for the (1 + y) / (1 - y) formula.
  static final BigInt one = BigInt.one;

  /// Convert a 32-byte Ed25519 public key to its X25519 (Montgomery u) form.
  ///
  /// Returns null when the point is not mappable (y == 1 or y == -1 mod p),
  /// which per RFC 7748 must be rejected rather than silently producing a
  /// degenerate key.
  static Uint8List? publicKey(Uint8List ed25519PublicKey) {
    if (ed25519PublicKey.length != 32) return null;

    // Little-endian, and the most significant bit is ignored.
    final le = Uint8List.fromList(ed25519PublicKey);
    le[31] &= 0x7f;

    final y = _littleEndianToBigInt(le);
    if (y >= p) return null;

    final denominator = mod((one - y), p);
    if (denominator == BigInt.zero) return null; // y == 1

    final numerator = mod((one + y), p);
    final u = mod(numerator * denominator.modInverse(p), p);

    return _bigIntToLittleEndian(u, 32);
  }

  /// Non-negative modular reduction (BigInt % keeps the dividend's sign).
  static BigInt mod(BigInt value, BigInt modulus) {
    final r = value % modulus;
    return r.isNegative ? r + modulus : r;
  }

  static BigInt _littleEndianToBigInt(Uint8List bytes) {
    // Assemble as sum(byte[i] * 256^i).
    var result = BigInt.zero;
    for (var i = bytes.length - 1; i >= 0; i--) {
      result = (result << 8) | BigInt.from(bytes[i]);
    }
    return result;
  }

  static Uint8List _bigIntToLittleEndian(BigInt value, int length) {
    final out = Uint8List(length);
    var v = value;
    for (var i = 0; i < length; i++) {
      out[i] = (v & BigInt.from(0xff)).toInt();
      v = v >> 8;
    }
    return out;
  }
}
