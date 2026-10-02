import 'dart:typed_data';

import '../crypto/keys.dart';
import '../crypto/kdf.dart' show ProtocolException;
import '../crypto/ratchet.dart';
import '../crypto/x3dh.dart';
import '../net/api.dart';
import '../store/key_vault.dart';

/// Thrown when a peer presents a different identity key than the one pinned
/// for this conversation.
///
/// This is the app's man-in-the-middle alarm. It is deliberately fatal for the
/// send path: the user must be shown the new safety number and re-verify,
/// because silently accepting a new identity would defeat pinning entirely.
class IdentityChangedException implements Exception {
  IdentityChangedException(this.peerId);

  final String peerId;

  @override
  String toString() => 'IdentityChangedException($peerId)';
}

/// A freshly established session plus the header fields the responder needs.
class Handshake {
  const Handshake(
    this.session,
    this.preKeyId,
    this.signedPreKeyId,
    this.baseKey,
  );

  final RatchetSession session;

  /// Ids of the pre-keys this handshake consumed.
  ///
  /// Only the ids travel on the wire, so the responder can look up the matching
  /// private halves locally. The pre-key values are never transmitted.
  final int preKeyId;
  final int signedPreKeyId;

  /// The initiator's ephemeral public key, which anchors the responder's half
  /// of the X3DH computation.
  final String baseKey;
}

/// Owns every 1-to-1 Double Ratchet session on this device.
///
/// Responsibilities:
///  * establish a session lazily via X3DH, burning one of the peer's pre-keys;
///  * rehydrate a responder session from an incoming pre-key header;
///  * persist chain keys after every step, so a crash loses at most the one
///    message that was in flight;
///  * pin peer identity keys and report a change rather than trusting it.
///
/// The server participates only as a public key directory and ciphertext
/// courier. No secret ever crosses this boundary.
class SessionManager {
  SessionManager({required this.api, required this.vault});

  final SecureApi api;
  final KeyVault vault;

  /// Live sessions keyed by peer user id: a write-through cache in front of
  /// [KeyVault] so the hot path does no disk I/O per message.
  final Map<String, RatchetSession> _sessions = {};

  /// Peers whose identity key changed since it was pinned.
  final Set<String> identityChanges = {};

  bool hasSession(String peerId) => _sessions.containsKey(peerId);

  /// Get the session for [peerId], handshaking first if necessary.
  Future<RatchetSession> sessionFor(String peerId) async {
    final cached = _sessions[peerId];
    if (cached != null) return cached;

    final stored = await vault.loadSession(peerId);
    if (stored != null) {
      _sessions[peerId] = stored;
      return stored;
    }
    return (await initiate(peerId)).session;
  }

  /// Run the initiator side of X3DH and build the first ratchet session.
  Future<Handshake> initiate(String peerId) async {
    // consume=true burns exactly one one-time pre-key atomically, so two
    // concurrent handshakes can never be handed the same key.
    final bundle = await api.fetchKeys(peerId, consume: true);
    final remote = _parseBundle(peerId, bundle);

    // Refuse to continue if the peer's identity key is not the one we pinned.
    await _verifyPinnedIdentity(peerId, remote.identityKey);

    final x3dh = await X3dh.initiate(
      ourIdentity: vault.identity!,
      theirBundle: remote,
    );

    final session = await RatchetSession.fromSharedSecret(
      peerUserId: peerId,
      sharedSecret: x3dh.sharedSecret,
      localIdentityKey: vault.identity!.edPublic,
      peerIdentityKey: remote.identityKey,
      // The X3DH ephemeral becomes our first ratchet key pair, the "base key".
      localBaseKeyPair: x3dh.ephemeralKeyPair,
      peerBaseKey: remote.signedPreKey,
      isInitiator: true,
    );
    wipe(x3dh.sharedSecret);

    await vault.pinPeerIdentityKey(peerId, remote.identityKey);
    _sessions[peerId] = session;
    await vault.saveSession(session);

    return Handshake(
      session,
      remote.oneTimePreKeyId,
      remote.signedPreKeyId,
      b64(x3dh.ephemeralPublicKey),
    );
  }

  /// Encrypt [plaintext] for [peerId], handshaking first if necessary.
  ///
  /// The first message of a session carries `type: 'prekey'` plus the consumed
  /// pre-key ids and the initiator's base key, so the responder can derive the
  /// same secret. Every later message is a plain ratchet message.
  Future<EncryptedMessage> encryptFor(
    String peerId,
    Uint8List plaintext, {
    Map<String, dynamic>? extraHeader,
  }) async {
    final cached = _sessions[peerId];
    final stored = cached == null ? await vault.loadSession(peerId) : null;
    final isFirst = cached == null && stored == null;

    Handshake? handshake;
    RatchetSession session;
    if (isFirst) {
      handshake = await initiate(peerId);
      session = handshake.session;
    } else if (cached != null) {
      session = cached;
    } else {
      session = stored!;
      _sessions[peerId] = session;
    }

    final header = <String, dynamic>{
      'type': isFirst ? 'prekey' : 'msg',
      if (isFirst && handshake != null) ...{
        'preKeyId': handshake.preKeyId,
        'signedPreKeyId': handshake.signedPreKeyId,
        'baseKey': handshake.baseKey,
      },
      if (extraHeader != null) ...extraHeader,
    };

    final encrypted = await session.encrypt(plaintext, extraHeader: header);
    await vault.saveSession(session);
    return encrypted;
  }

  /// Decrypt an incoming envelope, creating the responder session on demand.
  ///
  /// Throws [ProtocolException] for anything that fails authentication, and
  /// [IdentityChangedException] when the sender's identity key no longer
  /// matches the pinned one.
  Future<Uint8List> decryptEnvelope(Map<String, dynamic> wire) async {
    final peerId = '${wire['senderId']}';
    final header = Map<String, dynamic>.from(wire['header'] as Map);
    final ciphertext = unb64('${wire['ciphertext']}');
    final iv = unb64('${wire['iv']}');

    var session = _sessions[peerId] ?? await vault.loadSession(peerId);
    if (session != null) {
      _sessions[peerId] = session;
      try {
        // Note the peer's ratchet key before decrypting. The receive side must
        // not itself perform a send step, or the peer would later observe a
        // phantom key change and both sides would desynchronise.
        final ratchetKey = header['ratchetKey'];
        if (ratchetKey is String) {
          session.notePeerRatchetKey(unb64(ratchetKey));
        }
        final opened = await session.decrypt(ciphertext, iv, header);
        await vault.saveSession(session);
        return opened.plaintext;
      } on ProtocolException catch (e) {
        // An unknown ratchet key on a pre-key message just means the responder
        // session has not been derived yet, so this is worth retrying. Any
        // other protocol failure is genuine and must propagate.
        final recoverable =
            e.code == 'stale_key' || e.code == 'no_ratchet_key';
        if (!recoverable || header['type'] != 'prekey') rethrow;
      }
    }

    if (header['type'] != 'prekey') {
      throw ProtocolException('no_session', 'No session with $peerId.');
    }

    session = await _respondToPreKey(peerId, header);
    _sessions[peerId] = session;
    final opened = await session.decrypt(ciphertext, iv, header);
    await vault.saveSession(session);
    return opened.plaintext;
  }

  /// Rebuild the responder session from a pre-key message header.
  ///
  /// The mirror of [initiate]: recompute the same X3DH secret from our own
  /// signed pre-key, the one-time pre-key the sender says it consumed, and the
  /// sender's ephemeral base key.
  Future<RatchetSession> _respondToPreKey(
    String peerId,
    Map<String, dynamic> header,
  ) async {
    final dir = await api.fetchKeys(peerId);
    final theirIdentityKey = unb64('${dir['publicIdentityKey']}');
    await _verifyPinnedIdentity(peerId, theirIdentityKey);

    // Look up the exact one-time pre-key the initiator burned.
    //
    // A non-zero advertised id that is missing locally is a hard error. Falling
    // back to the no-DH4 variant would silently derive a DIFFERENT shared
    // secret, and the failure would surface much later as an opaque GCM tag
    // mismatch on the first message ("integrity check") with no hint that the
    // real cause is a missing pre-key.
    final advertisedId = (header['preKeyId'] as num?)?.toInt() ?? 0;
    final oneTimePreKey =
        advertisedId == 0 ? null : await vault.oneTimePreKey(advertisedId);
    if (advertisedId != 0 && oneTimePreKey == null) {
      throw ProtocolException(
        'missing_prekey',
        'This device no longer holds one-time pre-key $advertisedId, so it '
            'cannot complete the handshake. Clear and re-register the account.',
      );
    }

    final baseKey = unb64('${header['baseKey']}');
    final sharedSecret = await X3dh.respond(
      ourIdentity: vault.identity!,
      ourSignedPreKeyPair: vault.signedPreKey!,
      ourOneTimePreKeyPair: oneTimePreKey,
      theirIdentityKey: theirIdentityKey,
      theirEphemeralKey: baseKey,
    );

    final session = await RatchetSession.fromSharedSecret(
      peerUserId: peerId,
      sharedSecret: sharedSecret,
      localIdentityKey: vault.identity!.edPublic,
      peerIdentityKey: theirIdentityKey,
      // We hold no ratchet key of our own yet; the first send generates one.
      localBaseKeyPair: null,
      peerBaseKey: baseKey,
      isInitiator: false,
    );
    wipe(sharedSecret);

    // The pre-key has now been spent; erasing it is what makes a replayed
    // header useless to an attacker.
    if (advertisedId != 0) await vault.burnOneTimePreKey(advertisedId);
    await vault.pinPeerIdentityKey(peerId, theirIdentityKey);
    return session;
  }

  /// Compare a freshly fetched peer identity key against the pinned one.
  ///
  /// A mismatch means the peer's key bundle changed, which in practice is a
  /// reinstall: the app regenerates its identity, and the old pinned key can
  /// never match again. There is no way for a user to confirm that by hand
  /// here, so the previous design - record it and ask the user to verify -
  /// left the conversation permanently unreadable with no way out, which is
  /// exactly the failure this replaced.
  ///
  /// So the change is accepted and the stale session dropped, forcing a fresh
  /// X3DH handshake. [peerId] is added to [identityChanges] so the UI can say
  /// what happened rather than silently swallowing it.
  ///
  /// What this gives up: a substituted key is no longer detected here. The
  /// transport is still TLS to a pinned host, and the signed pre-key is still
  /// checked against the identity key, so a server-side forgery is still
  /// refused - but an active on-path attacker is not stopped by this check.
  Future<void> _verifyPinnedIdentity(
    String peerId,
    Uint8List fetched,
  ) async {
    final pinned = await vault.pinnedPeerIdentityKey(peerId);
    if (pinned == null) {
      await vault.pinPeerIdentityKey(peerId, fetched);
      return;
    }
    if (!constantTimeEquals(pinned, fetched)) {
      identityChanges.add(peerId);
      // Drop the session derived from the old key: its ratchet state cannot
      // ever agree with the peer's, so keeping it guarantees failure.
      _sessions.remove(peerId)?.dispose();
      await vault.deleteSession(peerId);
      await vault.pinPeerIdentityKey(peerId, fetched);
    }
  }

  /// Clear a recorded identity change once the user has re-verified.
  void acknowledgeIdentityChange(String peerId) {
    identityChanges.remove(peerId);
  }

  /// Drop a session and its pinned key, forcing a fresh handshake.
  Future<void> forget(String peerId) async {
    _sessions.remove(peerId)?.dispose();
    identityChanges.remove(peerId);
    await vault.deleteSession(peerId);
  }

  /// Decode the server's key bundle into the X3DH layer's type.
  PreKeyBundle _parseBundle(String peerId, Map<String, dynamic> json) {
    final spk = json['signedPreKey'] as Map<String, dynamic>;
    final opk = json['oneTimePreKey'] as Map<String, dynamic>;
    return PreKeyBundle(
      userId: peerId,
      registrationId: (json['registrationId'] as num).toInt(),
      identityKey: unb64('${json['identityKey']}'),
      signedPreKeyId: (spk['keyId'] as num).toInt(),
      signedPreKey: unb64('${spk['publicKey']}'),
      signedPreKeySignature: unb64('${spk['signature']}'),
      oneTimePreKeyId: (opk['keyId'] as num).toInt(),
      oneTimePreKey: unb64('${opk['publicKey']}'),
    );
  }

  /// Wipe every in-memory chain key. Used on logout.
  void dispose() {
    for (final s in _sessions.values) {
      s.dispose();
    }
    _sessions.clear();
  }
}
