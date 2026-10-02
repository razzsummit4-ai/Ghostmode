import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' show sha256;
import 'package:uuid/uuid.dart';

import '../crypto/keys.dart';
import '../crypto/kdf.dart' show ProtocolException;
import '../crypto/media_crypto.dart';
import '../crypto/safety.dart';
import '../net/api.dart' show ApiException;
import '../session/session_manager.dart';
import '../state/app_state.dart';
import '../state/chat_store.dart';

/// The decrypted shape of a message body.
///
/// Text and media travel inside the same encrypted envelope so the server sees
/// one opaque blob either way. Media additionally references a separately
/// encrypted file whose key is carried here.
class MessagePayload {
  const MessagePayload.text(this.text) : media = const {};
  const MessagePayload.media(this.text, this.media);

  /// Plaintext plus any attachment descriptor.
  const MessagePayload(this.text, [this.media = const {}]);

  final String text;
  final Map<String, dynamic> media;

  bool get hasMedia => media.isNotEmpty;

  String get kind => hasMedia ? 'media' : 'text';

  Map<String, dynamic> toJson() => {'t': text, 'm': media, 'k': kind};
}

/// Turns user intent into ciphertext on send, and ciphertext back into text on
/// receive.
///
/// This is the only place plaintext is produced or consumed, and it runs
/// entirely on-device. The server participates in neither direction.
class MessagingService {
  MessagingService({required this.state});

  final AppState state;

  static const _uuid = Uuid();

  /// Encrypt and send a text message.
  ///
  /// The row is inserted optimistically so the bubble appears immediately, then
  /// reconciled with the server id once the ciphertext is accepted.
  Future<ChatRow> sendText({
    required String chatId,
    required String peerId,
    String? groupId,
    required String text,
    int expiresInSeconds = 0,
  }) async {
    final clientMessageId = _uuid.v4();
    final payload = MessagePayload.text(text);

    final encrypted = await state.sessions.encryptFor(
      peerId,
      Uint8List.fromList(utf8.encode(jsonEncode(payload.toJson()))),
    );

    final row = ChatRow(
      clientMessageId: clientMessageId,
      chatId: chatId,
      senderId: state.userId ?? '',
      isMine: true,
      text: text,
      createdAt: DateTime.now(),
      status: 'sending',
      expiresAt: expiresInSeconds > 0
          ? DateTime.now().add(Duration(seconds: expiresInSeconds))
          : null,
    );
    state.chats.upsert(row);

    try {
      final res = await state.api.sendMessage(
        clientMessageId: clientMessageId,
        receiverId: groupId == null ? peerId : null,
        groupId: groupId,
        ciphertext: b64(encrypted.ciphertext),
        iv: b64(encrypted.iv),
        header: encrypted.header,
        envelope: {
          'type': payload.kind,
          'attachmentCount': 0,
          'expiresInSeconds': expiresInSeconds,
        },
      );
      final message = Map<String, dynamic>.from(res['message'] as Map);
      row.serverId = '${message['id']}';
      row.status = 'sent';
    } on ApiException catch (e) {
      // The bubble stays visible so the user can retry. The ratchet has already
      // advanced, so a retry re-encrypts from the new chain position.
      row.status = 'failed';
      // A 401 means the session is gone: the token expired, or the account was
      // removed on the server. Swallowing it would leave the user staring at a
      // failed bubble with no idea why, so record the reason and let the app
      // fall back to the sign-in screen.
      if (e.status == 401) {
        state.lastError = 'Session expired. Please sign in again.';
        await state.handleUnauthorized();
      } else {
        // Surface every other reason too. A silent failure here is what made
        // "message not sent" impossible to diagnose: the bubble just showed a
        // red tick and nothing said why.
        state.lastError = 'Not sent: ${e.message ?? e.code}';
      }
    } on ProtocolException catch (e) {
      // Encryption failed before anything was sent, so this is a local problem:
      // a missing or forged key, or a session that could not be established.
      row.status = 'failed';
      state.lastError = 'Not sent: ${e.detail ?? e.code}';
    } catch (e) {
      row.status = 'failed';
      state.lastError = 'Not sent: $e';
    }
    state.chats.upsert(row);
    return row;
  }

  /// Encrypt a file locally, upload only the ciphertext, then send the message.
  ///
  /// Order matters: the blob is sealed on this device and the file key travels
  /// inside the already-encrypted message body, so the storage backend never
  /// holds anything it could read.
  Future<ChatRow> sendMedia({
    required String chatId,
    required String peerId,
    String? groupId,
    required Uint8List bytes,
    required String fileName,
    required String mime,
    String kind = 'file',
    int expiresInSeconds = 0,
  }) async {
    final clientMessageId = _uuid.v4();
    final result = await MediaCrypto.encrypt(bytes, fileName, mime);

    // The server learns only a size and a coarse kind hint, never the name or
    // the contents.
    final presign = await state.api.presignUpload(
      size: result.blob.length,
      contentType: 'application/octet-stream',
      kind: kind,
    );
    final uploadUrl = '${presign['uploadUrl']}';
    await state.api.putBlob(uploadUrl, result.blob, 'application/octet-stream');

    final media = {
      ...result.keyEnvelope,
      'objectKey': '${presign['objectKey']}',
      'downloadUrl': uploadUrl,
      'kind': kind,
    };
    final label = captionFor(kind, fileName);
    final payload = MessagePayload.media(label, media);

    final encrypted = await state.sessions.encryptFor(
      peerId,
      Uint8List.fromList(utf8.encode(jsonEncode(payload.toJson()))),
    );

    final row = ChatRow(
      clientMessageId: clientMessageId,
      chatId: chatId,
      senderId: state.userId ?? '',
      isMine: true,
      text: label,
      kind: 'media',
      media: media,
      createdAt: DateTime.now(),
      status: 'sending',
      expiresAt: expiresInSeconds > 0
          ? DateTime.now().add(Duration(seconds: expiresInSeconds))
          : null,
    );
    state.chats.upsert(row);

    try {
      final res = await state.api.sendMessage(
        clientMessageId: clientMessageId,
        receiverId: groupId == null ? peerId : null,
        groupId: groupId,
        ciphertext: b64(encrypted.ciphertext),
        iv: b64(encrypted.iv),
        header: encrypted.header,
        envelope: {
          'type': 'media',
          'attachmentCount': 1,
          'expiresInSeconds': expiresInSeconds,
        },
      );
      final message = Map<String, dynamic>.from(res['message'] as Map);
      row.serverId = '${message['id']}';
      row.status = 'sent';
    } catch (_) {
      row.status = 'failed';
    }
    state.chats.upsert(row);
    return row;
  }

  /// Decrypt a single chat-list preview.
  ///
  /// The list endpoint returns one ciphertext message per conversation. It is
  /// decrypted here so the row can show real text, which is the whole point of
  /// a zero-knowledge server: it can only ever hand back the sealed form.
  Future<ChatRow?> loadPreview(
    dynamic summary,
    Map<String, dynamic> wire,
  ) async {
    final chatId = '${wire['chatId'] ?? summary.chatId}';
    final isMine = '${wire['senderId']}' == state.userId;
    final createdAt =
        DateTime.tryParse('${wire['createdAt']}') ?? DateTime.now();

    if (isMine) return null; // our own text is already on screen

    try {
      final plaintext = await state.sessions.decryptEnvelope(wire);
      final payload = _parsePayload(plaintext);
      return ChatRow(
        clientMessageId: '${wire['clientMessageId']}',
        serverId: '${wire['id']}',
        chatId: chatId,
        senderId: '${wire['senderId']}',
        isMine: false,
        text: payload.text,
        kind: payload.kind,
        media: payload.hasMedia ? payload.media : null,
        createdAt: createdAt,
        status: '${wire['status'] ?? 'sent'}',
      );
    } catch (e) {
      return ChatRow(
        clientMessageId: '${wire['clientMessageId']}',
        serverId: '${wire['id']}',
        chatId: chatId,
        senderId: '${wire['senderId']}',
        isMine: false,
        text: describeFailure(e),
        kind: 'undecryptable',
        createdAt: createdAt,
        status: '${wire['status'] ?? 'sent'}',
      );
    }
  }

  /// Load a thread's history and decrypt every message on this device.
  ///
  /// The server returns ciphertext only; each row is decrypted here before it
  /// reaches the UI. A message that fails authentication becomes a visible
  /// placeholder rather than being dropped, so tampering stays apparent.
  Future<void> loadThread(String chatId) async {
    final wire = await state.api.messages(chatId);
    final rows = <ChatRow>[];

    for (final m in wire) {
      final row = await _decryptRow(m, chatId);
      if (row != null) rows.add(row);
    }

    state.chats.replaceThread(chatId, rows);

    // Everything now on screen has been read.
    final pending = state.chats.pendingRead(chatId);
    if (pending.isNotEmpty) {
      state.chats.markReadLocally(chatId);
      await state.api.markStatus(pending, 'read');
    }
  }

  /// Decrypt one wire envelope into a [ChatRow], or null if there is nothing
  /// new to show.
  Future<ChatRow?> _decryptRow(
    Map<String, dynamic> wire,
    String chatId,
  ) async {
    final senderId = '${wire['senderId']}';
    final isMine = senderId == state.userId;
    final createdAt =
        DateTime.tryParse('${wire['createdAt']}') ?? DateTime.now();
    final envelope = Map<String, dynamic>.from(
      (wire['envelope'] as Map?) ?? const {'type': 'text'},
    );
    final expiresIn = (envelope['expiresInSeconds'] as num?)?.toInt() ?? 0;

    // Only the recipient holds the ratchet session, so a sender's own copy is
    // reconciled with the optimistic local row rather than decrypted.
    if (isMine) {
      for (final existing in state.chats.thread(chatId)) {
        if (existing.clientMessageId == '${wire['clientMessageId']}') {
          existing.serverId = '${wire['id']}';
          if (existing.status == 'sending') existing.status = 'sent';
          return existing;
        }
      }
      return null;
    }

    try {
      final plaintext = await state.sessions.decryptEnvelope(wire);
      final payload = _parsePayload(plaintext);
      return ChatRow(
        clientMessageId: '${wire['clientMessageId']}',
        serverId: '${wire['id']}',
        chatId: chatId,
        senderId: senderId,
        isMine: false,
        text: payload.text,
        kind: payload.kind,
        media: payload.hasMedia ? payload.media : null,
        createdAt: createdAt,
        status: '${wire['status'] ?? 'sent'}',
        expiresAt: expiresIn > 0
            ? createdAt.add(Duration(seconds: expiresIn))
            : null,
      );
    } catch (e) {
      return ChatRow(
        clientMessageId: '${wire['clientMessageId']}',
        serverId: '${wire['id']}',
        chatId: chatId,
        senderId: senderId,
        isMine: false,
        text: describeFailure(e),
        kind: 'undecryptable',
        createdAt: createdAt,
        status: '${wire['status'] ?? 'sent'}',
      );
    }
  }

  /// Decrypt a message that just arrived over the socket.
  Future<ChatRow?> handleIncoming(Map<String, dynamic> wire) async {
    final chatId = '${wire['chatId']}';
    if ('${wire['senderId']}' == state.userId) {
      // Our own message, echoed back after sending from another device.
      state.chats
          .applyReceipt(['${wire['id']}'], '${wire['status'] ?? 'sent'}');
      return null;
    }

    final row = await _decryptRow(wire, chatId);
    if (row == null) return null;
    state.chats.upsert(row);

    // Acknowledge delivery so the sender sees the double ticks.
    if (row.serverId.isNotEmpty) {
      unawaited(
        state.api
            .markStatus([row.serverId], 'delivered')
            .catchError((_) => <String, dynamic>{}),
      );
    }
    return row;
  }

  /// Decrypt an attached file using the key carried in the message body.
  ///
  /// The download is ciphertext; the file key came out of the ratchet, so the
  /// storage backend could never have read it.
  Future<Uint8List> downloadMedia(ChatRow row) async {
    final media = row.media;
    if (media == null) throw StateError('Message has no attachment.');
    final url = '${media['downloadUrl'] ?? media['objectKey']}';
    final blob = await state.api.getBlob(url);
    return MediaCrypto.decrypt(blob, media);
  }

  /// Compute the 60-digit safety number for a conversation.
  ///
  /// Derived from BOTH public identity keys, so each device independently
  /// arrives at the same digits. A middleman who substituted either key changes
  /// them, which is what makes out-of-band comparison meaningful.
  String safetyNumberFor(List<int> peerIdentityKey) {
    final local = state.localIdentityKey;
    if (local == null) return 'unavailable';
    return SafetyNumbers.compute(
      Uint8List.fromList(local),
      Uint8List.fromList(peerIdentityKey),
    );
  }

  /// A short, stable fingerprint of this device's own identity key.
  String get localFingerprint {
    final local = state.localIdentityKey;
    if (local == null) return 'unavailable';
    return fingerprintOf(local);
  }

  /// Short hex fingerprint of a public identity key, for the settings screen.
  static String fingerprintOf(List<int> edPublic) => sha256
      .convert(edPublic)
      .bytes
      .take(8)
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join();

  /// Decode a decrypted envelope body.
  MessagePayload _parsePayload(Uint8List plaintext) {
    try {
      final json = jsonDecode(utf8.decode(plaintext)) as Map<String, dynamic>;
      return MessagePayload(
        '${json['t'] ?? ''}',
        Map<String, dynamic>.from((json['m'] as Map?) ?? const {}),
      );
    } catch (_) {
      // Tolerate a non-JSON body so a legacy or malformed message still shows
      // its text instead of vanishing.
      return MessagePayload.text(utf8.decode(plaintext, allowMalformed: true));
    }
  }

  /// Human wording for a decryption failure, leaking no key material.
  static String describeFailure(Object e) {
    if (e is ProtocolException) {
      return switch (e.code) {
        // Say WHICH side of the tag failed. A bare "integrity check" sends the
        // user hunting for tampering, when the overwhelmingly likelier cause is
        // a desynchronised ratchet or a pre-key that was not found.
        'authentication_failed' =>
          '⚠️ Could not verify this message (wrong key on this device).',
        'missing_prekey' =>
          '⚠️ This device is missing the pre-key for that conversation.',
        'duplicate_message' => 'Duplicate message.',
        'no_session' => '⚠️ No encryption session with this contact yet.',
        'no_ratchet_key' => '⚠️ Message arrived before the session was ready.',
        _ => '⚠️ This message could not be decrypted.',
      };
    }
    return '⚠️ This message could not be decrypted.';
  }

  /// Short caption shown on a media bubble.
  static String captionFor(String kind, String fileName) => switch (kind) {
        'image' => '📷 Photo',
        'video' => '🎬 Video',
        'audio' => '🎵 Audio',
        _ => '📎 $fileName',
      };
}
