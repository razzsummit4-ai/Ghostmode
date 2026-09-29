import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'kdf.dart';
import 'keys.dart';

/// A message key, wiped after one use.
class MessageKey {
  MessageKey(this._key);
  final Uint8List _key;
  Uint8List take() {
    final k = Uint8List.fromList(_key);
    wipe(_key);
    return k;
  }
  void dispose() => wipe(_key);
}

/// One encrypted message as it goes onto the wire.
class EncryptedMessage {
  const EncryptedMessage({
    required this.ciphertext,
    required this.iv,
    required this.header,
  });
  final Uint8List ciphertext;
  final Uint8List iv;
  final Map<String, dynamic> header;
  Map<String, dynamic> toWire() => {
        'ciphertext': b64(ciphertext),
        'iv': b64(iv),
        'header': header,
      };
}

/// A decrypted plaintext plus authenticating header.
class DecryptedMessage {
  const DecryptedMessage(this.plaintext, this.header);
  final Uint8List plaintext;
  final Map<String, dynamic> header;
}
/// Double Ratchet session, Signal single-DH variant.
///
/// Every DH step mixes ONE secret; sender mixes DH(newSend, peerKey) and the
/// receiver later mixes DH(ownSend, newPeerKey). X25519 commutativity makes
/// them identical, so both sides derive the same root key. Chains point in a
/// direction: my sending chain mirrors the peer receiving chain.
class RatchetSession {
  RatchetSession({
    required this.peerUserId,
    required this.associatedData,
    required Uint8List rootKey,
    required Uint8List sendChainKey,
    required Uint8List receiveChainKey,
    required this.sendCounter,
    required this.receiveCounter,
    DhKeyPair? sendingRatchetKeyPair,
    Uint8List? receivingRatchetKey,
    Uint8List? pendingPeerRatchetKey,
    Uint8List? previousReceiveChainKey,
    int? previousReceiveCounter,
    Uint8List? previousReceivingRatchetKey,
    Map<String, MessageKey>? skippedKeys,
  })  : _rootKey = rootKey,
        _sendChainKey = sendChainKey,
        _receiveChainKey = receiveChainKey,
        _sendingRatchetKeyPair = sendingRatchetKeyPair,
        _receivingRatchetKey = receivingRatchetKey,
        _pendingPeerRatchetKey = pendingPeerRatchetKey,
        _previousReceiveChainKey = previousReceiveChainKey,
        _previousReceiveCounter = previousReceiveCounter,
        _previousReceivingRatchetKey = previousReceivingRatchetKey,
        _skippedKeys = skippedKeys ?? <String, MessageKey>{};

  final String peerUserId;
  final Uint8List associatedData;
  Uint8List _rootKey;
  Uint8List _sendChainKey;
  Uint8List _receiveChainKey;
  DhKeyPair? _sendingRatchetKeyPair;
  Uint8List? _receivingRatchetKey;
  Uint8List? _pendingPeerRatchetKey;
  Uint8List? _previousReceiveChainKey;
  int? _previousReceiveCounter;
  Uint8List? _previousReceivingRatchetKey;
  int sendCounter;
  int receiveCounter;
  final Map<String, MessageKey> _skippedKeys;
  bool get isInitialised => _sendingRatchetKeyPair != null;

  static Future<RatchetSession> fromSharedSecret({
    required String peerUserId,
    required Uint8List sharedSecret,
    required Uint8List localIdentityKey,
    required Uint8List peerIdentityKey,
    required DhKeyPair? localBaseKeyPair,
    required Uint8List peerBaseKey,
    required bool isInitiator,
  }) async {
    final rootKey =
        await Kdf.hkdf(sharedSecret, info: 'SecureChat/RatchetRoot/v1');
    final chainA = await Kdf.hkdf(rootKey, info: 'SecureChat/ChainA/v1');
    final chainB = await Kdf.hkdf(rootKey, info: 'SecureChat/ChainB/v1');
    return RatchetSession(
      peerUserId: peerUserId,
      associatedData:
          canonicalAssociatedData(localIdentityKey, peerIdentityKey),
      rootKey: rootKey,
      sendChainKey: isInitiator ? chainA : chainB,
      receiveChainKey: isInitiator ? chainB : chainA,
      sendCounter: 0,
      receiveCounter: 0,
      sendingRatchetKeyPair: isInitiator ? localBaseKeyPair : null,
      receivingRatchetKey:
          isInitiator ? null : Uint8List.fromList(peerBaseKey),
    );
  }

  static Uint8List canonicalAssociatedData(Uint8List a, Uint8List b) {
    final x = b64(Uint8List.fromList(a));
    final y = b64(Uint8List.fromList(b));
    return Uint8List.fromList(
        utf8.encode(x.compareTo(y) <= 0 ? '$x|$y' : '$y|$x'));
  }
  static RatchetSession fromJson(Map<String, dynamic> j) {
    final skipped = <String, MessageKey>{};
    final raw = j['skippedKeys'];
    if (raw is Map) {
      raw.forEach((k, v) => skipped['$k'] = MessageKey(unb64('$v')));
    }
    return RatchetSession(
      peerUserId: j['peerUserId'] as String,
      associatedData: unb64(j['associatedData'] as String),
      rootKey: unb64(j['rootKey'] as String),
      sendChainKey: unb64(j['sendChainKey'] as String),
      receiveChainKey: unb64(j['receiveChainKey'] as String),
      sendCounter: (j['sendCounter'] as num).toInt(),
      receiveCounter: (j['receiveCounter'] as num).toInt(),
      sendingRatchetKeyPair: j['sendingRatchetKey'] == null
          ? null
          : DhKeyPair.fromStored(
              publicKey: unb64(j['sendingRatchetPublicKey'] as String),
              privateKey: unb64(j['sendingRatchetKey'] as String),
            ),
      receivingRatchetKey: j['receivingRatchetKey'] == null
          ? null
          : unb64(j['receivingRatchetKey'] as String),
      pendingPeerRatchetKey: j['pendingPeerRatchetKey'] == null
          ? null
          : unb64(j['pendingPeerRatchetKey'] as String),
      previousReceiveChainKey: j['previousReceiveChainKey'] == null
          ? null
          : unb64(j['previousReceiveChainKey'] as String),
      previousReceiveCounter: (j['previousReceiveCounter'] as num?)?.toInt(),
      previousReceivingRatchetKey: j['previousReceivingRatchetKey'] == null
          ? null
          : unb64(j['previousReceivingRatchetKey'] as String),
      skippedKeys: skipped,
    );
  }

  Map<String, dynamic> toJson() => {
        'peerUserId': peerUserId,
        'associatedData': b64(associatedData),
        'rootKey': b64(_rootKey),
        'sendChainKey': b64(_sendChainKey),
        'receiveChainKey': b64(_receiveChainKey),
        'sendCounter': sendCounter,
        'receiveCounter': receiveCounter,
        'sendingRatchetKey': _sendingRatchetKeyPair?.privateBase64,
        'sendingRatchetPublicKey': _sendingRatchetKeyPair?.publicBase64,
        'receivingRatchetKey':
            _receivingRatchetKey == null ? null : b64(_receivingRatchetKey!),
        'pendingPeerRatchetKey':
            _pendingPeerRatchetKey == null ? null : b64(_pendingPeerRatchetKey!),
        'previousReceiveChainKey': _previousReceiveChainKey == null
            ? null
            : b64(_previousReceiveChainKey!),
        'previousReceiveCounter': _previousReceiveCounter,
        'previousReceivingRatchetKey': _previousReceivingRatchetKey == null
            ? null
            : b64(_previousReceivingRatchetKey!),
        'skippedKeys': {
          for (final e in _skippedKeys.entries) e.key: b64(e.value._key)
        },
      };

  void notePeerRatchetKey(Uint8List k) {
    if (_receivingRatchetKey != null &&
        constantTimeEquals(_receivingRatchetKey!, k)) {
      return;
    }
    if (_previousReceivingRatchetKey != null &&
        constantTimeEquals(_previousReceivingRatchetKey!, k)) {
      return;
    }
    if (_pendingPeerRatchetKey == null ||
        !constantTimeEquals(_pendingPeerRatchetKey!, k)) {
      _pendingPeerRatchetKey = Uint8List.fromList(k);
    }
  }
  static Future<(Uint8List, Uint8List)> kdfRk(
      Uint8List rk, Uint8List dh) async {
    final okm = await Kdf.hkdf(rk,
        info: 'SecureChat/DHRatchet/v1', salt: dh, length: 64);
    final a = Uint8List.fromList(okm.sublist(0, 32));
    final b = Uint8List.fromList(okm.sublist(32, 64));
    wipe(okm);
    return (a, b);
  }

  Future<EncryptedMessage> encrypt(Uint8List pt,
      {Map<String, dynamic>? extraHeader}) async {
    if (_sendingRatchetKeyPair == null) {
      await _receiveStepOnFirstSend();
    } else if (_pendingPeerRatchetKey != null) {
      await _sendRatchetStep(_pendingPeerRatchetKey!);
      _pendingPeerRatchetKey = null;
    }
    final mk = await Kdf.deriveMessageKey(_sendChainKey);
    final nx = await Kdf.deriveNextChainKey(_sendChainKey);
    wipe(_sendChainKey);
    _sendChainKey = nx;
    final header = <String, dynamic>{
      'type': 'msg',
      'ratchetKey': b64(_sendingRatchetKeyPair!.publicKey),
      'counter': sendCounter,
      if (extraHeader != null) ...extraHeader,
    };
    sendCounter++;
    final sealed = await aesGcm256.encrypt(
      pt,
      secretKey: SecretKey(mk),
      nonce: secureRandomBytes(12),
      aad: _aad(header),
    );
    wipe(mk);
    final wire =
        Uint8List.fromList([...sealed.cipherText, ...sealed.mac.bytes]);
    return EncryptedMessage(
      ciphertext: wire,
      iv: Uint8List.fromList(sealed.nonce),
      header: header,
    );
  }
  Future<void> _receiveStepOnFirstSend() async {
    final peerKey = _receivingRatchetKey;
    if (peerKey == null) {
      throw ProtocolException(
          'no_ratchet_key', 'Responder must send after handshake.');
    }
    final ours = await DhKeyPair.generate();
    final dh = await dhWith(ours, peerKey);
    final res = await kdfRk(_rootKey, dh);
    wipe(dh);
    wipe(_rootKey);
    _rootKey = res.$1;
    wipe(_sendChainKey);
    _sendChainKey = res.$2;
    _sendingRatchetKeyPair = ours;
    sendCounter = 0;
  }

  Future<void> _sendRatchetStep(Uint8List peerKey) async {
    final ours = await DhKeyPair.generate();
    final dh = await dhWith(ours, peerKey);
    final res = await kdfRk(_rootKey, dh);
    wipe(dh);
    wipe(_rootKey);
    _rootKey = res.$1;
    wipe(_sendChainKey);
    _sendChainKey = res.$2;
    _sendingRatchetKeyPair = ours;
    sendCounter = 0;
  }

  Future<void> _receiveRatchetStep(Uint8List peerKey) async {
    final ours = _sendingRatchetKeyPair;
    if (ours == null) {
      _receivingRatchetKey = Uint8List.fromList(peerKey);
      _pendingPeerRatchetKey = null;
      receiveCounter = 0;
      return;
    }
    if (_previousReceiveChainKey != null) {
      wipe(_previousReceiveChainKey!);
    }
    _previousReceiveChainKey = Uint8List.fromList(_receiveChainKey);
    _previousReceiveCounter = receiveCounter;
    _previousReceivingRatchetKey = _receivingRatchetKey == null
        ? null
        : Uint8List.fromList(_receivingRatchetKey!);
    final dh = await dhWith(ours, peerKey);
    final res = await kdfRk(_rootKey, dh);
    wipe(dh);
    wipe(_rootKey);
    _rootKey = res.$1;
    wipe(_receiveChainKey);
    _receiveChainKey = res.$2;
    _receivingRatchetKey = Uint8List.fromList(peerKey);
    _pendingPeerRatchetKey = null;
    receiveCounter = 0;
  }
  Future<DecryptedMessage> decrypt(
      Uint8List ct, Uint8List iv, Map<String, dynamic> header) async {
    final rk = unb64(header['ratchetKey'] as String);
    final rkB64 = b64(rk);
    final n = (header['counter'] as num).toInt();
    final hit = _skippedKeys.remove('$rkB64|$n');
    if (hit != null) {
      return DecryptedMessage(await _openGcm(ct, iv, header, hit), header);
    }
    final cur = _receivingRatchetKey;
    if (cur == null || !constantTimeEquals(cur, rk)) {
      final prev = _previousReceivingRatchetKey;
      final isPrev = prev != null && constantTimeEquals(prev, rk);
      if (!isPrev) {
        await _receiveRatchetStep(rk);
      } else if (_previousReceiveChainKey == null) {
        throw ProtocolException('stale_key', 'No chain for old key.');
      }
    }
    if (_previousReceiveChainKey != null &&
        _previousReceiveCounter != null &&
        _previousReceivingRatchetKey != null &&
        constantTimeEquals(_previousReceivingRatchetKey!, rk) &&
        n < _previousReceiveCounter!) {
      final steps = _previousReceiveCounter! - n;
      final key = await keyFromPrev(_previousReceiveChainKey!, steps);
      if (key != null) {
        return DecryptedMessage(await _openGcm(ct, iv, header, key), header);
      }
    }
    if (n < receiveCounter) {
      throw ProtocolException('duplicate_message', 'Key already used.');
    }
    if (n > receiveCounter) {
      await skipTo(rkB64, n);
    }
    final mk = await Kdf.deriveMessageKey(_receiveChainKey);
    final nx = await Kdf.deriveNextChainKey(_receiveChainKey);
    wipe(_receiveChainKey);
    _receiveChainKey = nx;
    receiveCounter = n + 1;
    return DecryptedMessage(
      await _openGcm(ct, iv, header, MessageKey(mk)),
      header,
    );
  }
  Future<void> skipTo(String rkB64, int until) async {
    var chain = Uint8List.fromList(_receiveChainKey);
    var c = receiveCounter;
    const maxSkip = 1000;
    final target = (c + maxSkip) < until ? c + maxSkip : until;
    final derived = <int, Uint8List>{};
    while (c < target) {
      derived[c] = await Kdf.deriveMessageKey(chain);
      final nx = await Kdf.deriveNextChainKey(chain);
      wipe(chain);
      chain = nx;
      c++;
    }
    wipe(_receiveChainKey);
    _receiveChainKey = chain;
    receiveCounter = target;
    for (final e in derived.entries) {
      if (_skippedKeys.length >= 2000) break;
      _skippedKeys['$rkB64|${e.key}'] = MessageKey(e.value);
    }
  }

  Future<MessageKey?> keyFromPrev(Uint8List ck, int steps) async {
    var chain = Uint8List.fromList(ck);
    MessageKey? found;
    for (var i = 0; i < steps; i++) {
      final mk = await Kdf.deriveMessageKey(chain);
      if (i == steps - 1) {
        found = MessageKey(mk);
      } else {
        wipe(mk);
      }
      final nx = await Kdf.deriveNextChainKey(chain);
      wipe(chain);
      chain = nx;
    }
    wipe(chain);
    return found;
  }

  Future<Uint8List> _openGcm(
      Uint8List ct, Uint8List iv, Map<String, dynamic> h, MessageKey k) async {
    final key = k.take();
    try {
      const tagLen = 16;
      if (ct.length < tagLen) throw ProtocolException('ciphertext_too_short');
      final body = ct.sublist(0, ct.length - tagLen);
      final tag = ct.sublist(ct.length - tagLen);
      final clear = await aesGcm256.decrypt(
        SecretBox(body, nonce: iv, mac: Mac(tag)),
        secretKey: SecretKey(key),
        aad: _aad(h),
      );
      return Uint8List.fromList(clear);
    } on SecretBoxAuthenticationError {
      throw ProtocolException('authentication_failed', 'GCM tag mismatch.');
    } finally {
      wipe(key);
    }
  }

  List<int> _aad(Map<String, dynamic> h) =>
      utf8.encode('${canonicalHeader(h)}|${b64(associatedData)}');

  static String canonicalHeader(Map<String, dynamic> h) {
    final ks = h.keys.toList()..sort();
    return jsonEncode({for (final k in ks) k: h[k]});
  }

  static Future<Uint8List> dhWith(DhKeyPair o, List<int> t) async {
    final s = await x25519.sharedSecretKey(
      keyPair: o.keyPair,
      remotePublicKey: SimplePublicKey(
        Uint8List.fromList(t),
        type: KeyPairType.x25519,
      ),
    );
    return Uint8List.fromList(await s.extractBytes());
  }

  void dispose() {
    wipe(_rootKey);
    wipe(_sendChainKey);
    wipe(_receiveChainKey);
    if (_previousReceiveChainKey != null) wipe(_previousReceiveChainKey!);
    for (final k in _skippedKeys.values) {
      k.dispose();
    }
    _skippedKeys.clear();
  }
}
