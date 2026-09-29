import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'keys.dart';
import 'kdf.dart';

/// One group Sender Key chain: a chain key plus its iteration.
///
/// Each group member owns one chain and fans its public sender key out over
/// pairwise sessions. Messages advance the chain with HKDF so every message
/// key is fresh (forward secrecy inside the group too).
class SenderKeyState {
  SenderKeyState({
    required this.groupId,
    required this.senderId,
    required this.senderKeyId,
    required Uint8List chainKey,
    this.iteration = 0,
  }) : _chainKey = chainKey;

  final String groupId;
  final String senderId;
  final String senderKeyId;
  Uint8List _chainKey;
  int iteration;

  Uint8List get chainKey => Uint8List.fromList(_chainKey);

  Map<String, dynamic> toJson() => {
        'groupId': groupId,
        'senderId': senderId,
        'senderKeyId': senderKeyId,
        'chainKey': b64(_chainKey),
        'iteration': iteration,
      };

  static SenderKeyState fromJson(Map<String, dynamic> j) => SenderKeyState(
        groupId: j['groupId'] as String,
        senderId: j['senderId'] as String,
        senderKeyId: j['senderKeyId'] as String,
        chainKey: unb64(j['chainKey'] as String),
        iteration: (j['iteration'] as num).toInt(),
      );

  void dispose() => wipe(_chainKey);
}
/// Sender-Key ratchet for group messaging.
///
/// The group server only routes ciphertext. Each member generates its own
/// chain (`createOwn`), distributes the (chainKey, keyId) over pairwise
/// E2E sessions, and encrypts group messages with per-message keys.
/// Late-joiners / reordered packets are handled with a small skipped-key
/// cache, mirroring the 1:1 ratchet.
class GroupRatchet {
  GroupRatchet._();

  /// Fresh chain for this device to send with in [groupId].
  static SenderKeyState createOwn({required String groupId, required String senderId}) {
    return SenderKeyState(
      groupId: groupId,
      senderId: senderId,
      senderKeyId: b64(secureRandomBytes(16)),
      chainKey: secureRandomBytes(32),
    );
  }

  /// Envelope a receiver must accept to install a peer's sender key.
  static Map<String, dynamic> distributionEnvelope(SenderKeyState s) => {
        'type': 'groupkey',
        'groupId': s.groupId,
        'senderId': s.senderId,
        'senderKeyId': s.senderKeyId,
        'chainKey': b64(s.chainKey),
        'iteration': s.iteration,
      };

  /// Install a peer's sender key from a pairwise-decrypted envelope.
  static SenderKeyState receiveDistribution(Map<String, dynamic> e) {
    return SenderKeyState(
      groupId: e['groupId'] as String,
      senderId: e['senderId'] as String,
      senderKeyId: e['senderKeyId'] as String,
      chainKey: unb64(e['chainKey'] as String),
      iteration: (e['iteration'] as num?)?.toInt() ?? 0,
    );
  }

  /// Encrypt one group message. Advances the sender chain.
  static Future<EncryptedGroupMessage> encrypt(
    SenderKeyState sender,
    Uint8List plaintext, {
    int expiresInSeconds = 0,
  }) async {
    final mk = await Kdf.hkdf(
      sender._chainKey,
      info: 'SecureChat/GroupMsg/v1',
      salt: _u32(sender.iteration),
      length: 32,
    );
    final nonce = secureRandomBytes(12);
    final aad = utf8.encode(
        'group|${sender.groupId}|${sender.senderKeyId}|${sender.iteration}');
    final sealed = await aesGcm256.encrypt(
      plaintext,
      secretKey: SecretKey(mk),
      nonce: nonce,
      aad: aad,
    );
    wipe(mk);
    final next = await Kdf.hkdf(
      sender._chainKey,
      info: 'SecureChat/GroupChain/v1',
      salt: _u32(sender.iteration + 1),
      length: 32,
    );
    wipe(sender._chainKey);
    sender._chainKey = next;
    final header = {
      'type': 'group',
      'senderKeyId': sender.senderKeyId,
      'senderChainId': 1,
      'senderIteration': sender.iteration,
    };
    sender.iteration++;
    return EncryptedGroupMessage(
      ciphertext: Uint8List.fromList([...sealed.cipherText, ...sealed.mac.bytes]),
      iv: Uint8List.fromList(sealed.nonce),
      header: header,
      expiresInSeconds: expiresInSeconds,
    );
  }
}

/// Decrypt one group message against the matching peer chain.
class GroupReceiver {
  final Map<String, SenderKeyState> chains = {};
  final Map<String, Uint8List> _skipped = {};

  String _id(String senderId, String keyId) => '$senderId|$keyId';

  void install(SenderKeyState s) {
    final old = chains[_id(s.senderId, s.senderKeyId)];
    old?.dispose();
    chains[_id(s.senderId, s.senderKeyId)] = s;
  }

  /// Serialise every installed chain plus the skipped-key cache, so a restart
  /// can still decrypt messages that arrived out of order while offline.
  Map<String, dynamic> toJson() => {
        'chains': {
          for (final e in chains.entries) e.key: e.value.toJson(),
        },
        'skipped': {
          for (final e in _skipped.entries) e.key: b64(e.value),
        },
      };

  static GroupReceiver fromJson(Map<String, dynamic> j) {
    final r = GroupReceiver();
    final chains = j['chains'];
    if (chains is Map) {
      chains.forEach((k, v) {
        try {
          r.chains['$k'] =
              SenderKeyState.fromJson(Map<String, dynamic>.from(v as Map));
        } catch (_) {
          // Skip a chain we cannot parse rather than losing all of them.
        }
      });
    }
    final skipped = j['skipped'];
    if (skipped is Map) {
      skipped.forEach((k, v) {
        try {
          r._skipped['$k'] = unb64('$v');
        } catch (_) {
          // Ignore an unreadable skipped key; the sender will re-derive it.
        }
      });
    }
    return r;
  }

  /// Wipe every chain key and skipped key held for this group.
  void dispose() {
    for (final c in chains.values) {
      c.dispose();
    }
    chains.clear();
    for (final k in _skipped.values) {
      wipe(k);
    }
    _skipped.clear();
  }

  /// Decrypt; tolerates gaps up to 1000 iterations via skipped keys.
  Future<Uint8List> decrypt({
    required String groupId,
    required String senderId,
    required Map<String, dynamic> header,
    required Uint8List ciphertext,
    required Uint8List iv,
  }) async {
    final keyId = header['senderKeyId'] as String;
    final n = (header['senderIteration'] as num).toInt();
    final id = _id(senderId, keyId);
    final skipHit = _skipped.remove('$id|$n');
    if (skipHit != null) {
      try {
        return await _open(groupId, keyId, n, ciphertext, iv, skipHit);
      } finally {
        wipe(skipHit);
      }
    }
    final chain = chains[id];
    if (chain == null) {
      throw ProtocolException('no_sender_key', 'Unknown sender key $id.');
    }
    if (n < chain.iteration) {
      throw ProtocolException('duplicate_group_message');
    }
    var steps = n - chain.iteration;
    if (steps > 1000) steps = 1000;
    for (var i = 0; i < steps; i++) {
      final mk = await Kdf.hkdf(chain._chainKey,
          info: 'SecureChat/GroupMsg/v1',
          salt: _u32(chain.iteration),
          length: 32);
      if (_skipped.length < 2000) {
        _skipped['$id|${chain.iteration}'] = mk;
      } else {
        wipe(mk);
      }
      final next = await Kdf.hkdf(chain._chainKey,
          info: 'SecureChat/GroupChain/v1',
          salt: _u32(chain.iteration + 1),
          length: 32);
      wipe(chain._chainKey);
      chain._chainKey = next;
      chain.iteration++;
    }
    final mk = await Kdf.hkdf(chain._chainKey,
        info: 'SecureChat/GroupMsg/v1',
        salt: _u32(chain.iteration),
        length: 32);
    final next = await Kdf.hkdf(chain._chainKey,
        info: 'SecureChat/GroupChain/v1',
        salt: _u32(chain.iteration + 1),
        length: 32);
    wipe(chain._chainKey);
    chain._chainKey = next;
    chain.iteration++;
    try {
      return await _open(groupId, keyId, n, ciphertext, iv, mk);
    } finally {
      wipe(mk);
    }
  }

  Future<Uint8List> _open(String groupId, String keyId, int n,
      Uint8List ct, Uint8List iv, Uint8List mk) async {
    const tagLen = 16;
    if (ct.length < tagLen) throw ProtocolException('ciphertext_too_short');
    final aad = utf8.encode('group|$groupId|$keyId|$n');
    try {
      final clear = await aesGcm256.decrypt(
        SecretBox(ct.sublist(0, ct.length - tagLen),
            nonce: iv, mac: Mac(ct.sublist(ct.length - tagLen))),
        secretKey: SecretKey(mk),
        aad: aad,
      );
      return Uint8List.fromList(clear);
    } on SecretBoxAuthenticationError {
      throw ProtocolException('authentication_failed', 'GCM tag mismatch.');
    }
  }
}

/// Ciphertext of one group message, ready for POST /api/messages.
class EncryptedGroupMessage {
  EncryptedGroupMessage({
    required this.ciphertext,
    required this.iv,
    required this.header,
    this.expiresInSeconds = 0,
  });

  final Uint8List ciphertext;
  final Uint8List iv;
  final Map<String, dynamic> header;
  final int expiresInSeconds;
}

Uint8List _u32(int v) =>
    Uint8List(4)..buffer.asByteData().setUint32(0, v, Endian.big);
