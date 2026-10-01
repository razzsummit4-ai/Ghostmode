import 'dart:async';

import 'package:socket_io_client/socket_io_client.dart' as io;

import '../core/config.dart';

/// Socket.io gateway for live ciphertext, receipts and typing.
///
/// The socket never persists anything and never sees plaintext: it relays the
/// same opaque envelopes that `POST /api/messages` already stored. Even a fully
/// compromised transport therefore reveals nothing.
class RealtimeGateway {
  io.Socket? _socket;

  /// Newest `createdAt` seen on the wire, used as the cursor for the next
  /// `sync:request`. Null until the first inbound message or batch.
  String? _lastSyncedAt;

  final _messages = StreamController<Map<String, dynamic>>.broadcast();
  final _receipts = StreamController<ReceiptEvent>.broadcast();
  final _typing = StreamController<TypingEvent>.broadcast();
  final _connection = StreamController<bool>.broadcast();

  /// Raw incoming envelopes. Consumers decrypt these themselves.
  Stream<Map<String, dynamic>> get messages => _messages.stream;

  Stream<ReceiptEvent> get receipts => _receipts.stream;
  Stream<TypingEvent> get typing => _typing.stream;
  Stream<bool> get connection => _connection.stream;

  bool get connected => _socket?.connected ?? false;

  Future<void> connect(String token) async {
    _socket?.dispose();
    final socket = io.io(
      AppConfig.apiBaseUrl,
      io.OptionBuilder()
          .setTransports(['websocket'])
          .setAuth({'token': token})
          .enableReconnection()
          .setReconnectionDelay(1200)
          .build(),
    );
    _socket = socket;

    socket.onConnect((_) {
      if (!_connection.isClosed) _connection.add(true);
      // Ask for anything missed while the device was offline or asleep.
      //
      // The cursor must be the last timestamp this device actually processed.
      // Sending "now" - as this did - asks for messages created after the
      // moment of connecting, which is always an empty set, so anything that
      // arrived while the socket was down was never recovered. Zero means
      // "everything I have not already de-duplicated by clientMessageId",
      // which is safe because the client reconciles on its own id.
      socket.emitWithAck(
        'sync:request',
        {'after': _lastSyncedAt ?? ''},
        ack: (_) {},
      );
    });

    socket.onDisconnect((_) {
      if (!_connection.isClosed) _connection.add(false);
    });

    socket.onConnectError((_) {
      if (!_connection.isClosed) _connection.add(false);
    });

    socket.on('message:receive', _onMessage);
    socket.on('message:new', _onMessage);

    // The server answers `sync:request` with a batch on this event. Without a
    // listener the batch is received and discarded, so anything recovered
    // after a reconnect never reached the message stream.
    socket.on('sync:batch', (data) {
      final rows = (data is Map ? data['messages'] : null);
      if (rows is! List) return;
      for (final row in rows) {
        if (row is Map) _onMessage(row);
      }
    });

    socket.on('message:delivered', (data) {
      if (data is Map) {
        _receipts.add(
          ReceiptEvent(
            messageIds: _idsOf(data),
            status: 'delivered',
            at: '${data['at'] ?? ''}',
          ),
        );
      }
    });

    socket.on('message:read', (data) {
      if (data is Map) {
        _receipts.add(
          ReceiptEvent(
            messageIds: _idsOf(data),
            status: 'read',
            at: '${data['at'] ?? ''}',
          ),
        );
      }
    });

    socket.on('typing', (data) {
      if (data is Map) {
        _typing.add(
          TypingEvent(
            userId: '${data['userId'] ?? ''}',
            receiverId: data['receiverId'] as String?,
            groupId: data['groupId'] as String?,
            typing: data['typing'] == true,
          ),
        );
      }
    });

    socket.connect();
  }

  void _onMessage(dynamic data) {
    if (data is! Map) return;
    if (!_messages.isClosed) {
      _messages.add(Map<String, dynamic>.from(data));
    }
    // Advance the sync cursor from the payload, not from the clock. Anything
    // the device has seen is something the next `sync:request` must not ask
    // for again; using a local timestamp instead would drop messages that
    // arrived while this device's clock disagreed with the server's.
    final at = data['createdAt'];
    if (at is String && at.isNotEmpty) {
      final previous = _lastSyncedAt;
      if (previous == null || at.compareTo(previous) > 0) _lastSyncedAt = at;
    }
  }

  static List<String> _idsOf(Map<dynamic, dynamic> data) =>
      ((data['messageIds'] as List?) ?? const []).map((e) => '$e').toList();

  /// Tell a peer we are typing. Carries presence only, never content.
  void sendTyping({String? receiverId, String? groupId, bool typing = true}) {
    _socket?.emit('typing', {
      if (receiverId != null) 'receiverId': receiverId,
      if (groupId != null) 'groupId': groupId,
      'typing': typing,
    });
  }

  /// Report that messages reached the device or were read.
  void sendReceipt({
    required List<String> messageIds,
    required String status,
    required String senderId,
  }) {
    _socket?.emitWithAck(
      'receipt',
      {'messageIds': messageIds, 'status': status, 'senderId': senderId},
      ack: (_) {},
    );
  }

  void joinGroup(String groupId) {
    _socket?.emitWithAck('group:join', {'groupId': groupId}, ack: (_) {});
  }

  void leaveGroup(String groupId) {
    _socket?.emit('group:leave', {'groupId': groupId});
  }

  /// Tear down the socket but keep the streams open for reconnect.
  void disconnect() {
    _socket?.dispose();
    _socket = null;
  }

  Future<void> dispose() async {
    _socket?.dispose();
    _socket = null;
    if (!_messages.isClosed) await _messages.close();
    if (!_receipts.isClosed) await _receipts.close();
    if (!_typing.isClosed) await _typing.close();
    if (!_connection.isClosed) await _connection.close();
  }
}

/// A delivery or read receipt relayed by the server.
class ReceiptEvent {
  const ReceiptEvent({
    required this.messageIds,
    required this.status,
    required this.at,
  });

  final List<String> messageIds;
  final String status;
  final String at;
}

/// A peer's typing state. Contains no content by design.
class TypingEvent {
  const TypingEvent({
    required this.userId,
    this.receiverId,
    this.groupId,
    required this.typing,
  });

  final String userId;
  final String? receiverId;
  final String? groupId;
  final bool typing;
}
