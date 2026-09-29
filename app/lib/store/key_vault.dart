import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../crypto/keys.dart';
import '../crypto/ratchet.dart';
import '../crypto/sender_key.dart';

/// A batch of freshly minted one-time pre-keys plus the id the first was stored
/// under.
///
/// The id is carried rather than recomputed by the caller, because the only
/// correct value is the one the vault already wrote. A top-up must continue the
/// numbering, not restart it at 1.
class MintedPreKeys {
  const MintedPreKeys({required this.pairs, required this.startId});

  final List<DhKeyPair> pairs;

  /// Id of [pairs]' first element; the rest are consecutive from here.
  final int startId;

  int get length => pairs.length;

  /// Public halves tagged with the ids the vault actually stored them under.
  List<Map<String, dynamic>> get published => [
        for (var i = 0; i < pairs.length; i++)
          {'keyId': startId + i, 'publicKey': pairs[i].publicBase64},
      ];
}

/// Everything secret that lives on this device.
///
/// Private key material is written **only** through [FlutterSecureStorage],
/// which is backed by the Android Keystore (values encrypted under a
/// hardware-bound key) and the iOS Keychain. No private half, chain key or
/// session state is ever written to SharedPreferences, to a file, to a log, or
/// to the network.
///
/// Public material is safe to publish and is what [publicBundleForUpload]
/// returns; the private halves of those same keys stay behind in this vault
/// and are never part of that object.
class KeyVault {
  KeyVault({FlutterSecureStorage? storage})
      : _storage = storage ?? const FlutterSecureStorage();

  final FlutterSecureStorage _storage;

  // Key names are namespaced and versioned so a schema change cannot silently
  // collide with, or be mistaken for, older material.
  static const _kIdentitySeed = 'sc.v1.identity.seed';
  static const _kSignedKeyId = 'sc.v1.spk.id';
  static const _kSignedPub = 'sc.v1.spk.pub';
  static const _kSignedPriv = 'sc.v1.spk.priv';
  static const _kOneTimeNextId = 'sc.v1.opk.next_id';
  static const _kDeviceId = 'sc.v1.device.id';
  static const _kOneTimePrefix = 'sc.v1.opk.';
  static const _kSessionPrefix = 'sc.v1.session.';
  static const _kSenderKeyPrefix = 'sc.v1.senderkey.';
  static const _kGroupReceiverPrefix = 'sc.v1.grouprecv.';
  static const _kPeerIkPrefix = 'sc.v1.peerik.';

  IdentityKeyPair? _identity;
  DhKeyPair? _signedPreKey;
  int _signedPreKeyId = 1;

  IdentityKeyPair? get identity => _identity;
  DhKeyPair? get signedPreKey => _signedPreKey;
  int get signedPreKeyId => _signedPreKeyId;
  bool get isInitialised => _identity != null;

  /// Restore keys from secure storage. Returns false on a fresh install.
  Future<bool> load() async {
    final seedB64 = await _storage.read(key: _kIdentitySeed);
    if (seedB64 == null) return false;
    try {
      _identity = await IdentityKeyPair.fromSeed(unb64(seedB64));

      final pub = await _storage.read(key: _kSignedPub);
      final priv = await _storage.read(key: _kSignedPriv);
      final idRaw = await _storage.read(key: _kSignedKeyId);
      if (pub != null && priv != null) {
        _signedPreKey = DhKeyPair.fromStored(
          publicKey: unb64(pub),
          privateKey: unb64(priv),
        );
        _signedPreKeyId = int.tryParse(idRaw ?? '') ?? 1;
      }
      return true;
    } catch (_) {
      // A corrupt vault is treated as a fresh install. Generating a new
      // identity is safe; reusing a half-read one is not.
      _identity = null;
      _signedPreKey = null;
      return false;
    }
  }

  /// Generate a brand-new identity and signed pre-key, then persist them.
  Future<void> generateFresh() async {
    final seed = secureRandomBytes(32);
    try {
      final identity = await IdentityKeyPair.fromSeed(seed);
      final spk = await DhKeyPair.generate();
      await _storage.write(key: _kIdentitySeed, value: b64(seed));
      await _storage.write(key: _kSignedPub, value: spk.publicBase64);
      await _storage.write(key: _kSignedPriv, value: spk.privateBase64);
      await _storage.write(key: _kSignedKeyId, value: '1');
      _identity = identity;
      _signedPreKey = spk;
      _signedPreKeyId = 1;
    } finally {
      wipe(seed);
    }
  }

  /// Rotate the signed pre-key, erasing the previous private half.
  ///
  /// Sessions established against the old pre-key stay valid, but an attacker
  /// who captured that private half cannot derive any future session.
  Future<void> rotateSignedPreKey() async {
    final fresh = await DhKeyPair.generate();
    _signedPreKey = fresh;
    _signedPreKeyId++;
    await _storage.write(key: _kSignedPub, value: fresh.publicBase64);
    await _storage.write(key: _kSignedPriv, value: fresh.privateBase64);
    await _storage.write(key: _kSignedKeyId, value: '$_signedPreKeyId');
  }

  /// Publishable bundle: public halves only, safe to POST to the server.
  ///
  /// Note the absence of any private field. The server's zero-knowledge guard
  /// rejects the request outright if a private half ever appears here.
  ///
  /// [oneTimeStartId] is REQUIRED, not defaulted. It must be the id the caller
  /// stored those private halves under, because the responder will use the
  /// published id to look one up again. Defaulting it to 1 is what previously
  /// let a top-up re-publish colliding ids and silently break the handshake.
  Future<Map<String, dynamic>> publicBundleForUpload({
    required List<DhKeyPair> oneTimePreKeys,
    required int oneTimeStartId,
  }) async {
    final id = _identity!;
    final spk = _signedPreKey!;
    final sig = await id.sign(spk.publicKey);
    return {
      'identityKey': id.publicBase64,
      'signedPreKey': {
        'keyId': _signedPreKeyId,
        'publicKey': spk.publicBase64,
        'signature': b64(sig.bytes),
      },
      'oneTimePreKeys': [
        for (var i = 0; i < oneTimePreKeys.length; i++)
          {
            'keyId': oneTimeStartId + i,
            'publicKey': oneTimePreKeys[i].publicBase64,
          },
      ],
    };
  }

  // --- One-time pre-keys -----------------------------------------------------
  //
  // Each pre-key services exactly one X3DH handshake. Its private half lives in
  // secure storage and is deleted as soon as the server confirms the key was
  // consumed, so it can never service two handshakes.

  static String _preKeyKey(int id) => '$_kOneTimePrefix$id';

  /// Mint [count] fresh pre-keys and persist their private halves.
  ///
  /// Returns the keys together with the id the FIRST one was stored under.
  ///
  /// That id matters and must travel with the keys. The server keys its pool by
  /// `keyId`, and the responder later looks its private half up by that same id.
  /// If the published ids did not match the local ones, the responder would
  /// recover the WRONG private half, derive a different X3DH secret, and every
  /// message would fail its GCM tag with a bare "integrity check" error.
  Future<MintedPreKeys> mintOneTimePreKeys(int count) async {
    final startId = await _nextPreKeyId();
    final out = <DhKeyPair>[];
    for (var i = 0; i < count; i++) {
      final pair = await DhKeyPair.generate();
      await _storage.write(
        key: _preKeyKey(startId + i),
        value: pair.privateBase64,
      );
      out.add(pair);
    }
    await _storage.write(key: _kOneTimeNextId, value: '${startId + count}');
    return MintedPreKeys(pairs: out, startId: startId);
  }

  /// Recover a consumed pre-key's private half (responder side of X3DH).
  ///
  /// The public half is unknown here because only the private half was kept;
  /// the responder never needs the public copy.
  Future<DhKeyPair?> oneTimePreKey(int keyId) async {
    final priv = await _storage.read(key: _preKeyKey(keyId));
    if (priv == null) return null;
    return DhKeyPair.fromStored(publicKey: const [], privateKey: unb64(priv));
  }

  /// Erase a pre-key's private half once the server has burned it.
  Future<void> burnOneTimePreKey(int keyId) =>
      _storage.delete(key: _preKeyKey(keyId));

  /// Ids of pre-keys whose private halves are still on this device.
  Future<List<int>> localOneTimePreKeyIds() async {
    final all = await _storage.readAll();
    final ids = <int>[];
    for (final key in all.keys) {
      if (!key.startsWith(_kOneTimePrefix)) continue;
      final parsed = int.tryParse(key.substring(_kOneTimePrefix.length));
      if (parsed != null) ids.add(parsed);
    }
    ids.sort();
    return ids;
  }

  /// How many handshakes this device can still answer.
  Future<int> localOneTimePreKeyCount() async =>
      (await localOneTimePreKeyIds()).length;

  Future<int> _nextPreKeyId() async {
    final raw = await _storage.read(key: _kOneTimeNextId);
    return int.tryParse(raw ?? '') ?? 1;
  }

  // --- Device identity -------------------------------------------------------

  /// Stable per-install device id, used by the multi-device pre-key model.
  Future<String> deviceId() async {
    var id = await _storage.read(key: _kDeviceId);
    if (id == null) {
      id = b64(secureRandomBytes(16));
      await _storage.write(key: _kDeviceId, value: id);
    }
    return id;
  }

  // --- Ratchet sessions ------------------------------------------------------

  /// Persist chain keys after every step.
  ///
  /// This is what makes a crash survivable: the chain advances on disk before
  /// the next message key is derived, so a restart resumes at the right
  /// position instead of reusing a message key.
  Future<void> saveSession(RatchetSession session) => _storage.write(
        key: '$_kSessionPrefix${session.peerUserId}',
        value: jsonEncode(session.toJson()),
      );

  Future<RatchetSession?> loadSession(String peerId) async {
    final raw = await _storage.read(key: '$_kSessionPrefix$peerId');
    if (raw == null) return null;
    try {
      return RatchetSession.fromJson(
        jsonDecode(raw) as Map<String, dynamic>,
      );
    } catch (_) {
      return null;
    }
  }

  Future<void> deleteSession(String peerId) =>
      _storage.delete(key: '$_kSessionPrefix$peerId');

  // --- Pinned peer identity keys --------------------------------------------
  //
  // Pinned on the first verified handshake. A later change is reported to the
  // user as a safety-number change rather than being silently accepted.

  Future<void> pinPeerIdentityKey(String peerId, Uint8List edPublic) =>
      _storage.write(key: '$_kPeerIkPrefix$peerId', value: b64(edPublic));

  Future<Uint8List?> pinnedPeerIdentityKey(String peerId) async {
    final raw = await _storage.read(key: '$_kPeerIkPrefix$peerId');
    return raw == null ? null : unb64(raw);
  }

  // --- Group sender keys -----------------------------------------------------

  Future<void> saveSenderKey(SenderKeyState state) => _storage.write(
        key: '$_kSenderKeyPrefix${state.groupId}',
        value: jsonEncode(state.toJson()),
      );

  Future<SenderKeyState?> loadSenderKey(String groupId) async {
    final raw = await _storage.read(key: '$_kSenderKeyPrefix$groupId');
    if (raw == null) return null;
    try {
      return SenderKeyState.fromJson(
        jsonDecode(raw) as Map<String, dynamic>,
      );
    } catch (_) {
      return null;
    }
  }

  Future<void> saveGroupReceiver(String groupId, GroupReceiver receiver) =>
      _storage.write(
        key: '$_kGroupReceiverPrefix$groupId',
        value: jsonEncode(receiver.toJson()),
      );

  Future<GroupReceiver?> loadGroupReceiver(String groupId) async {
    final raw = await _storage.read(key: '$_kGroupReceiverPrefix$groupId');
    if (raw == null) return null;
    try {
      return GroupReceiver.fromJson(
        jsonDecode(raw) as Map<String, dynamic>,
      );
    } catch (_) {
      return null;
    }
  }

  /// Irreversibly erase every key and session held by this app.
  ///
  /// Because ratchet chain keys are destroyed along with the identity, any
  /// message encrypted to this device becomes permanently undecryptable here.
  Future<void> destroy() async {
    await _storage.deleteAll();
    _identity = null;
    _signedPreKey = null;
    _signedPreKeyId = 1;
  }
}
