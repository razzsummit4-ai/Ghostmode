import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:flutter/foundation.dart';
import 'package:flutter_nearby_connections/flutter_nearby_connections.dart';

/// A device seen on the local mesh.
class GhostDevice {
  const GhostDevice({required this.id, required this.name});

  final String id;
  final String name;
}

/// A message that travelled over the offline mesh.
class GhostMessage {
  GhostMessage({
    required this.id,
    required this.from,
    required this.to,
    required this.text,
    required this.type,
    required this.time,
    this.isMine = false,
  });

  final String id;
  final String from;
  final String to;
  final String text;
  final String type;
  final DateTime time;
  final bool isMine;
}

/// Offline peer-to-peer mesh over the Nearby Connections API.
///
/// ## Security warning - read this before building on this
///
/// **Messages on this channel are NOT end-to-end encrypted.** The payload is
/// plain UTF-8 text, broadcast to every device in radio range, and relayed
/// onward by those devices. Anyone running the app nearby, or any device
/// tapping the same traffic, reads the content in clear.
///
/// This deliberately does not pretend otherwise. It exists for the "no signal"
/// case where a server round-trip is impossible, and the UI carries a permanent
/// warning. The encrypted channel is the one in the chat list: those messages
/// are AES-256-GCM under a Double Ratchet that relay nodes cannot compute.
///
/// To make this channel safe it would have to carry a ciphertext envelope
/// authenticated against the recipient's identity key, with relays unable to
/// read it. Until that exists this is a convenience, not a security boundary.
class OfflineGhostService extends ChangeNotifier {
  OfflineGhostService({NearbyService? service})
      : _service = service ?? NearbyService();

  final NearbyService _service;

  /// `Random.secure()`, not `Random()`: these ids gate de-duplication and relay
  /// suppression, so a predictable generator would let a peer collide ids and
  /// suppress legitimate traffic.
  final Random _rand = Random.secure();

  /// Nearby Connections caps the service type at 15 characters.
  static const String _serviceType = 'mp-connection';

  final List<GhostDevice> nearbyDevices = [];
  final List<GhostMessage> messages = [];

  /// Message ids already handled, so a relayed packet is processed once.
  ///
  /// Bounded on purpose: an unbounded set would grow for the life of the
  /// process, and a mesh node relays whatever it is sent.
  final Set<String> seenMessageIds = <String>{};

  /// Most recent ids retained; older ones are evicted.
  static const int _maxSeenIds = 2000;

  /// Oldest messages dropped from the view. This is a live radio channel, not a
  /// mailbox.
  static const int _maxMessages = 500;

  StreamSubscription<dynamic>? _stateSub;
  StreamSubscription<dynamic>? _dataSub;

  late String myName;
  bool isRunning = false;

  /// Set when the platform reports an unrecoverable error.
  String? lastError;

  bool _disposed = false;
  bool _ready = false;

  /// Bring the mesh up: init the plugin, then advertise and browse at once.
  ///
  /// Doing both is what lets two phones find each other with neither having to
  /// be designated the host.
  Future<void> start() async {
    if (isRunning) return;
    _assignName();
    isRunning = true;
    lastError = null;
    _safeNotify();

    try {
      await _service.init(
        serviceType: _serviceType,
        strategy: Strategy.P2P_CLUSTER,
        deviceName: myName,
        callback: (running) {
          // The plugin reports the radio actually coming up asynchronously.
          isRunning = running == true;
          _safeNotify();
        },
      );

      _stateSub =
          _service.stateChangedSubscription(callback: _onStateChanged);
      _dataSub = _service.dataReceivedSubscription(callback: _onDataReceived);

      _ready = true;
      await _service.startAdvertisingPeer();
      await _service.startBrowsingForPeers();
    } catch (e) {
      lastError = 'Nearby connections unavailable: $e';
      isRunning = false;
      _ready = false;
      _safeNotify();
    }
  }

  /// A fresh random name per session.
  ///
  /// Deliberately not the account identity: this channel has no authentication,
  /// so reusing a real name would imply a trust relationship that does not exist.
  void _assignName() {
    myName = 'ghost_${_rand.nextInt(9000) + 1000}';
  }

  /// The plugin pushes the whole peer list on every state change.
  void _onStateChanged(dynamic devices) {
    if (_disposed || devices is! List) return;
    final connected = <GhostDevice>[];
    for (final device in devices) {
      if (device is! Device) continue;
      if (device.state != SessionState.connected) continue;
      final name = device.deviceName;
      // Guard against the plugin handing back an empty name, which would render
      // as a blank chip the user cannot select.
      if (name.isEmpty) continue;
      if (connected.any((d) => d.name == name)) continue;
      connected.add(GhostDevice(id: device.deviceId, name: name));
    }

    final unchanged = connected.length == nearbyDevices.length &&
        connected.every(nearbyDevices.contains);
    if (unchanged) return;

    nearbyDevices
      ..clear()
      ..addAll(connected);
    _safeNotify();
  }

  void _onDataReceived(dynamic data) {
    if (_disposed || data is! String) return;
    _handlePacket(data);
  }

  /// Handle one inbound packet.
  ///
  /// Malformed input is dropped silently: this channel is open to anything in
  /// range, so it must not be a source of crashes or log spam.
  void _handlePacket(String raw) {
    try {
      final decoded = jsonDecode(raw);
      if (decoded is! Map) return;
      final data = Map<String, dynamic>.from(decoded);

      final id = data['id'];
      final from = data['from'];
      final to = data['to'];
      final text = data['text'];
      if (id is! String ||
          from is! String ||
          to is! String ||
          text is! String) {
        return;
      }
      if (seenMessageIds.contains(id)) return;

      // Bound the dedup set, evicting the oldest entry first.
      if (seenMessageIds.length >= _maxSeenIds) {
        seenMessageIds.remove(seenMessageIds.first);
      }
      seenMessageIds.add(id);

      final message = GhostMessage(
        id: id,
        from: from,
        to: to,
        text: text,
        type: '${data['type'] ?? 'broadcast'}',
        time: DateTime.tryParse('${data['time']}') ?? DateTime.now(),
      );

      if (to == 'ALL' || to == myName) {
        _append(message);
      }

      // Relay anything not addressed to us, so the message keeps travelling
      // past a single hop. Never bounce it back to the sender.
      if (to != myName) {
        _relay(raw, excludeName: from);
      }
    } catch (_) {
      // Not our protocol, or truncated. Ignore.
    }
  }

  void _append(GhostMessage message) {
    if (_disposed) return;
    messages.add(message);
    if (messages.length > _maxMessages) {
      messages.removeRange(0, messages.length - _maxMessages);
    }
    _safeNotify();
  }

  /// Send a packet to every connected peer except one.
  void _relay(String raw, {String? excludeName}) {
    for (final device in nearbyDevices) {
      if (excludeName != null && device.name == excludeName) continue;
      _send(device.id, raw);
    }
  }

  void _send(String deviceId, String raw) {
    if (!_ready) return;
    // Fire-and-forget: a peer that vanished mid-send must not break the loop.
    // sendMessage is declared FutureOr, so wrap it in a Future to catch both.
    unawaited(Future.sync(() => _service.sendMessage(deviceId, raw))
        .catchError((_) => null));
  }

  /// A new id for an outgoing message.
  String _newId() =>
      '${myName}_${DateTime.now().microsecondsSinceEpoch}_${_rand.nextInt(1 << 32)}';

  /// Send to everyone in range.
  void sendBroadcast(String text) {
    final trimmed = text.trim();
    if (trimmed.isEmpty || _disposed) return;

    final id = _newId();
    final now = DateTime.now();
    final packet = jsonEncode({
      'id': id,
      'from': myName,
      'to': 'ALL',
      'type': 'broadcast',
      'text': trimmed,
      'time': now.toIso8601String(),
    });

    seenMessageIds.add(id);
    _append(GhostMessage(
      id: id,
      from: myName,
      to: 'ALL',
      text: trimmed,
      type: 'broadcast',
      time: now,
      isMine: true,
    ));
    _relay(packet);
  }

  /// Send to one named peer.
  ///
  /// A whisper still crosses the air like any other packet. "private" here means
  /// "addressed to one device", NOT confidential, and the UI says so.
  void sendWhisper(String targetName, String text) {
    final trimmed = text.trim();
    if (trimmed.isEmpty || _disposed) return;

    final id = _newId();
    final now = DateTime.now();
    final packet = jsonEncode({
      'id': id,
      'from': myName,
      'to': targetName,
      'type': 'private',
      'text': trimmed,
      'time': now.toIso8601String(),
    });

    seenMessageIds.add(id);
    _append(GhostMessage(
      id: id,
      from: myName,
      to: targetName,
      text: trimmed,
      type: 'private',
      time: now,
      isMine: true,
    ));

    // Deliver only to the named peer, but it is still cleartext on the wire.
    for (final device in nearbyDevices) {
      if (device.name == targetName) _send(device.id, packet);
    }
  }

  /// Stop advertising, browsing and all connections.
  void stop() {
    isRunning = false;
    _ready = false;
    unawaited(_stateSub?.cancel());
    unawaited(_dataSub?.cancel());
    _stateSub = null;
    _dataSub = null;
    // Releases the radio. Without this the mesh keeps advertising after the
    // screen closes, which drains the battery.
    for (final closer in <FutureOr<dynamic> Function()>[
      _service.stopAdvertisingPeer,
      _service.stopBrowsingForPeers,
    ]) {
      try {
        unawaited(Future.sync(closer).catchError((_) => null));
      } catch (_) {
        // Already stopped.
      }
    }
    nearbyDevices.clear();
    _safeNotify();
  }

  /// Clear the transcript but keep the radio session.
  void clearHistory() {
    messages.clear();
    seenMessageIds.clear();
    _safeNotify();
  }

  void _safeNotify() {
    if (_disposed) return;
    notifyListeners();
  }

  @override
  void dispose() {
    stop();
    _disposed = true;
    super.dispose();
  }
}
