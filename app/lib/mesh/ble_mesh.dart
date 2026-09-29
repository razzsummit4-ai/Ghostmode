import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter_reactive_ble/flutter_reactive_ble.dart';
import 'package:permission_handler/permission_handler.dart';


/// Bitchat-style offline mesh: BLE advertisements carry E2E ciphertext
/// for ~100 m peer-to-peer delivery when the server is unreachable.
///
/// Security model is unchanged: the mesh transports the SAME Double
/// Ratchet envelopes (base64 ciphertext + iv + header). Relays cannot
/// read or modify anything; GCM authentication still fails on tampering.
/// This layer only replaces the transport (BLE instead of HTTPS/socket).
class BleMesh extends ChangeNotifier {
  final FlutterReactiveBle _ble = FlutterReactiveBle();
  bool scanning = false;
  bool advertising = false;
  final List<MeshPeer> peers = [];
  StreamSubscription<DiscoveredDevice>? _scanSub;

  static final Uuid serviceUuid =
      Uuid.parse('6e400001-b5a3-f393-e0a9-e50e24dcca9e');
  static final Uuid txChar =
      Uuid.parse('6e400003-b5a3-f393-e0a9-e50e24dcca9e');

  Future<bool> ensurePermissions() async {
    final req = await [
      Permission.bluetoothScan,
      Permission.bluetoothAdvertise,
      Permission.bluetoothConnect,
      Permission.locationWhenInUse,
    ].request();
    return req.values.every((s) => s.isGranted || s.isLimited);
  }

  Future<void> startScan() async {
    if (scanning) return;
    if (!await ensurePermissions()) return;
    scanning = true;
    notifyListeners();
    _scanSub = _ble.scanForDevices(
      withServices: [serviceUuid],
      scanMode: ScanMode.lowLatency,
    ).listen((d) {
      final id = d.id;
      if (peers.any((p) => p.id == id)) return;
      peers.add(MeshPeer(id: id, name: d.name, rssi: d.rssi));
      notifyListeners();
    });
  }

  Future<void> stopScan() async {
    await _scanSub?.cancel();
    _scanSub = null;
    scanning = false;
    notifyListeners();
  }

  /// Chunk + reassemble helper: BLE MTU is small so envelopes are split
  /// into 180-byte frames with a 4-byte header (msgId:2, idx:1, total:1).
  static List<Uint8List> frameEnvelope(Map<String, dynamic> env) {
    final raw = Uint8List.fromList(utf8.encode(jsonEncode(env)));
    const mtu = 180;
    final total = (raw.length / mtu).ceil();
    final msgId = DateTime.now().millisecondsSinceEpoch & 0xffff;
    final out = <Uint8List>[];
    for (var i = 0; i < total; i++) {
      final s = i * mtu;
      final e = (s + mtu > raw.length) ? raw.length : s + mtu;
      final frame = Uint8List(4 + (e - s));
      frame[0] = (msgId >> 8) & 0xff;
      frame[1] = msgId & 0xff;
      frame[2] = i;
      frame[3] = total;
      frame.setRange(4, 4 + (e - s), raw.sublist(s, e));
      out.add(frame);
    }
    return out;
  }
}

/// A nearby device seen over BLE (identity resolved after handshake).
class MeshPeer {
  MeshPeer({required this.id, required this.name, required this.rssi});
  final String id;
  final String name;
  final int rssi;
}

/// Reassembly buffer for chunked BLE frames.
class MeshReassembler {
  final Map<int, Map<int, Uint8List>> _parts = {};
  final Map<int, int> _totals = {};

  Map<String, dynamic>? push(Uint8List frame) {
    if (frame.length < 5) return null;
    final msgId = (frame[0] << 8) | frame[1];
    final idx = frame[2];
    final total = frame[3];
    _parts.putIfAbsent(msgId, () => {})[idx] = frame.sublist(4);
    _totals[msgId] = total;
    final parts = _parts[msgId]!;
    if (parts.length == total) {
      final out = <int>[];
      for (var i = 0; i < total; i++) {
        out.addAll(parts[i]!);
      }
      _parts.remove(msgId);
      _totals.remove(msgId);
      return jsonDecode(utf8.decode(out)) as Map<String, dynamic>;
    }
    return null;
  }
}
