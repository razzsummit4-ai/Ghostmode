import 'dart:typed_data';

import '../crypto/keys.dart';
import '../crypto/kdf.dart' show ProtocolException;
import '../crypto/sender_key.dart';
import '../state/app_state.dart';

/// Group messaging, using per-member Sender Key chains.
///
/// Each member owns one chain. Its sender key is distributed to every other
/// member over the existing pairwise encrypted 1:1 sessions, and group messages
/// are then sealed with a key derived from that chain.
///
/// The consequence that matters: the server routes group ciphertext and holds
/// no key that can open it. An operator who dumps the database sees only opaque
/// blobs, including for groups.
///
/// Forward secrecy holds inside the group too, because the chain advances on
/// every message, so each message key is used exactly once.
class GroupService {
  GroupService({required this.state});

  final AppState state;

  /// Create this device's sender key for [groupId] and hand back the
  /// distribution envelope to seal and send to each other member.
  ///
  /// Distribution travels over a 1:1 ratchet session, so only the intended
  /// recipient can read the chain key.
  Future<SenderKeyState> createSenderKey(String groupId) async {
    final senderKey = GroupRatchet.createOwn(
      groupId: groupId,
      senderId: state.userId ?? '',
    );
    await state.vault.saveSenderKey(senderKey);
    return senderKey;
  }

  /// The distribution envelope for one member.
  Map<String, dynamic> distributionFor(SenderKeyState senderKey) =>
      GroupRatchet.distributionEnvelope(senderKey);

  /// Adopt a peer sender key that arrived over a pairwise session.
  Future<void> installPeerSenderKey(
    String groupId,
    SenderKeyState peerChain,
  ) async {
    final receiver = await _receiverFor(groupId);
    receiver.install(peerChain);
    await state.vault.saveGroupReceiver(groupId, receiver);
  }

  /// Decrypt a group message.
  ///
  /// Returns null when the sending member's chain is not known yet, which
  /// happens if their distribution message has not arrived. The caller then
  /// holds the ciphertext and retries, rather than losing the message.
  Future<Uint8List?> decryptGroup(
    String groupId,
    Map<String, dynamic> wire,
  ) async {
    final header = Map<String, dynamic>.from(wire['header'] as Map);
    final receiver = await _receiverFor(groupId);

    try {
      return await receiver.decrypt(
        groupId: groupId,
        senderId: '${wire['senderId']}',
        header: header,
        ciphertext: unb64('${wire['ciphertext']}'),
        iv: unb64('${wire['iv']}'),
      );
    } on ProtocolException catch (e) {
      if (e.code == 'no_sender_key') return null;
      rethrow;
    }
  }

  /// Encrypt a group message with this device's sender key.
  ///
  /// The chain is created on first use, so a member who has never spoken in the
  /// group does not have to bootstrap it by hand.
  Future<EncryptedGroupMessage> encryptGroup(
    String groupId,
    Uint8List plaintext, {
    int expiresInSeconds = 0,
  }) async {
    final senderKey = await state.vault.loadSenderKey(groupId) ??
        await createSenderKey(groupId);
    final encrypted = await GroupRatchet.encrypt(
      senderKey,
      plaintext,
      expiresInSeconds: expiresInSeconds,
    );
    await state.vault.saveSenderKey(senderKey);
    return encrypted;
  }

  /// Decode a distribution envelope that arrived over a 1:1 session.
  SenderKeyState readDistribution(Map<String, dynamic> payload) =>
      GroupRatchet.receiveDistribution(payload);

  Future<GroupReceiver> _receiverFor(String groupId) async =>
      await state.vault.loadGroupReceiver(groupId) ?? GroupReceiver();
}
