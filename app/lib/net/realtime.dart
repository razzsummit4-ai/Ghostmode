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
      socket.emitWithAck(
        'sync:request',
        {'after': DateTime.now().toIso8601String()},
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
