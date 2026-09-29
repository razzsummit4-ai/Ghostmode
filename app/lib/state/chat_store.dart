import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/foundation.dart';

import '../crypto/keys.dart';

/// One decrypted message, as the UI sees it.
///
/// [text] is decrypted plaintext and exists ONLY in memory. It is never written
/// to disk, never sent to the server, and never included in a log. The durable
/// record for this message is ciphertext plus an IV and a header.
class ChatRow {
  ChatRow({
    required this.clientMessageId,
    required this.chatId,
    required this.senderId,
    required this.isMine,
    required this.text,
    required this.createdAt,
    this.serverId = '',
    this.status = 'sending',
    this.kind = 'text',
    this.media,
    this.expiresAt,
  });

  /// Client-generated id. Stable across retries, so the outbox reconciles.
  final String clientMessageId;

  /// Server id, empty until the message is persisted.
  String serverId;

  final String chatId;
  final String senderId;
  final bool isMine;

  /// Decrypted body. In-memory only.
  String text;

  final DateTime createdAt;

  /// One of: sending, sent, delivered, read, failed.
  String status;

  /// 'text', 'media', 'expired', or 'undecryptable'.
  String kind;

  /// Decrypted attachment descriptor (file key, name, mime, object key).
  Map<String, dynamic>? media;

  /// When a disappearing message should be removed locally.
  DateTime? expiresAt;

  bool get isMedia => kind == 'media';
  bool get failed => status == 'failed';
}

/// A conversation header for the chat list.
class ChatSummary {
  ChatSummary({
    required this.chatId,
    required this.type,
    required this.title,
    this.peerId,
    this.groupId,
    this.avatarColor = 0,
    this.lastMessage,
    this.unreadCount = 0,
    this.disappearingMessagesSeconds = 0,
  });

  final String chatId;
  final String type;
  final String title;
  final String? peerId;
  final String? groupId;
  final int avatarColor;

  /// The newest row, decrypted for display.
  ChatRow? lastMessage;

  int unreadCount;
  int disappearingMessagesSeconds;

  bool get isGroup => type == 'group';
}


/// In-memory chat state for the UI.
///
/// Holds decrypted plaintext for rendering and nothing more. The durable,
/// decryptable-on-demand record lives on the server as ciphertext; ratchet
/// state lives in the KeyVault. This store is intentionally NOT persisted, so
/// a cold start re-fetches ciphertext and decrypts it locally.
class ChatStore extends ChangeNotifier {
  final Map<String, List<ChatRow>> _threads = {};
  final Map<String, ChatSummary> _summaries = {};
  final Map<String, Timer> _expiryTimers = {};

  /// Peers currently typing, timestamped so the indicator can self-expire.
  final Map<String, DateTime> _typing = {};

  List<ChatRow> thread(String chatId) => _threads[chatId] ?? const [];

  ChatSummary? summary(String chatId) => _summaries[chatId];

  List<ChatSummary> get summaries {
    final list = _summaries.values.toList()
      ..sort((a, b) {
        final at =
            a.lastMessage?.createdAt ?? DateTime.fromMillisecondsSinceEpoch(0);
        final bt =
            b.lastMessage?.createdAt ?? DateTime.fromMillisecondsSinceEpoch(0);
        return bt.compareTo(at);
      });
    return list;
  }

  bool isPeerTyping(String peerId) {
    final at = _typing[peerId];
    if (at == null) return false;
    // An indicator that never clears would be a permanent lie about the peer's
    // state, so treat anything older than 6 s as stale.
    if (DateTime.now().difference(at) > const Duration(seconds: 6)) {
      _typing.remove(peerId);
      return false;
    }
    return true;
  }

  void setTyping(String peerId, bool typing) {
    if (typing) {
      _typing[peerId] = DateTime.now();
    } else {
      _typing.remove(peerId);
    }
    notifyListeners();
  }

  void clearTyping() {
    if (_typing.isEmpty) return;
    _typing.clear();
    notifyListeners();
  }

  /// Insert or replace a row, keyed by its stable client message id.
  void upsert(ChatRow row) {
    final list = _threads.putIfAbsent(row.chatId, () => <ChatRow>[]);
    final index =
        list.indexWhere((r) => r.clientMessageId == row.clientMessageId);
    if (index >= 0) {
      list[index] = row;
    } else {
      list.add(row);
      list.sort((a, b) => a.createdAt.compareTo(b.createdAt));
    }
    _summaries[row.chatId]?.lastMessage = list.isEmpty ? null : list.last;
    _scheduleExpiry(row);
    notifyListeners();
  }

  /// Replace a whole thread, e.g. after loading history.
  void replaceThread(String chatId, List<ChatRow> rows) {
    rows.sort((a, b) => a.createdAt.compareTo(b.createdAt));
    _threads[chatId] = rows;
    final summary = _summaries[chatId];
    if (summary != null) summary.lastMessage = rows.isEmpty ? null : rows.last;
    for (final r in rows) {
      _scheduleExpiry(r);
    }
    notifyListeners();
  }

  void setSummary(ChatSummary summary) {
    _summaries[summary.chatId] = summary;
    notifyListeners();
  }

  void removeSummary(String chatId) {
    _summaries.remove(chatId);
    notifyListeners();
  }

  /// Apply a delivery or read receipt to my own outgoing messages.
  void applyReceipt(List<String> serverIds, String status) {
    var changed = false;
    for (final list in _threads.values) {
      for (final row in list) {
        if (row.isMine && serverIds.contains(row.serverId)) {
          // Never downgrade a read receipt back to delivered.
          if (row.status == 'read' && status == 'delivered') continue;
          if (row.status != status) {
            row.status = status;
            changed = true;
          }
        }
      }
    }
    if (changed) notifyListeners();
  }

  /// Ids of incoming messages that still need a delivered receipt.
  List<String> pendingDelivered(String chatId) => thread(chatId)
      .where((r) => !r.isMine && r.status == 'sent' && r.serverId.isNotEmpty)
      .map((r) => r.serverId)
      .toList();

  List<String> pendingRead(String chatId) => thread(chatId)
      .where((r) => !r.isMine && r.status != 'read' && r.serverId.isNotEmpty)
      .map((r) => r.serverId)
      .toList();

  void markReadLocally(String chatId) {
    var changed = false;
    for (final row in thread(chatId)) {
      if (!row.isMine && row.status != 'read') {
        row.status = 'read';
        changed = true;
      }
    }
    _summaries[chatId]?.unreadCount = 0;
    if (changed) notifyListeners();
  }

  void incrementUnread(String chatId) {
    final summary = _summaries[chatId];
    if (summary == null) return;
    summary.unreadCount++;
    notifyListeners();
  }

  /// Schedule local removal of a disappearing message.
  ///
  /// The server also enforces a TTL on the stored ciphertext; this is the
  /// client-side half, so the message leaves the screen on time.
  void _scheduleExpiry(ChatRow row) {
    final at = row.expiresAt;
    if (at == null) return;
    _expiryTimers[row.clientMessageId]?.cancel();
    final delay = at.difference(DateTime.now());
    if (delay <= Duration.zero) {
      _expire(row);
      return;
    }
    _expiryTimers[row.clientMessageId] = Timer(delay, () => _expire(row));
  }

  void _expire(ChatRow row) {
    _expiryTimers.remove(row.clientMessageId);
    if (!_threads.containsKey(row.chatId)) return;
    // Overwrite the plaintext before dropping the reference, so a stale copy
    // lingering on the heap is less likely to be recovered.
    wipe(Uint8List.fromList(utf8.encode(row.text)));
    row.text = '';
    row.kind = 'expired';
    notifyListeners();
  }

  /// Drop a row the user discarded, e.g. a failed send being retried.
  void removeRow(String chatId, String clientMessageId) {
    _threads[chatId]?.removeWhere((r) => r.clientMessageId == clientMessageId);
    _expiryTimers.remove(clientMessageId)?.cancel();
    notifyListeners();
  }

  @override
  void dispose() {
    for (final t in _expiryTimers.values) {
      t.cancel();
    }
    _expiryTimers.clear();
    // Best-effort scrub of every plaintext still held.
    for (final list in _threads.values) {
      for (final row in list) {
        wipe(Uint8List.fromList(utf8.encode(row.text)));
        row.text = '';
      }
    }
    _threads.clear();
    _summaries.clear();
    super.dispose();
  }
}
