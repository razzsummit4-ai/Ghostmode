import 'dart:async';
import 'dart:convert';
import 'dart:io';

/// A SecureChat server found on the local network.
class DiscoveredServer {
  const DiscoveredServer({
    required this.name,
    required this.addresses,
    required this.httpPort,
    required this.publicUrl,
  });

  /// Friendly name the server advertises, e.g. "SecureChat server".
  final String name;

  /// Candidate LAN addresses, most likely to be usable first.
  final List<String> addresses;

  /// The port the HTTP API listens on.
  final int httpPort;

  /// The server's own idea of its public URL, if it has one.
  final String publicUrl;

  /// The advertised addresses, ordered by how likely this device is to reach
  /// them.
  ///
  /// A laptop commonly holds several addresses at once - Wi-Fi, a VPN adapter,
  /// a hotspot, Docker. Ranking the private ranges first means the default the
  /// user is offered is the one a phone on the same Wi-Fi can actually use.
  List<String> get usableAddresses {
    int rank(String address) {
      if (address.startsWith('192.168.') || address.startsWith('10.')) return 0;
      if (RegExp(r'^172\.(1[6-9]|2\d|3[01])\.').hasMatch(address)) return 0;
      if (address.startsWith('169.254.')) return 2; // link-local: rarely usable
      if (address.startsWith('127.')) return 3;
      return 1;
    }

    return [...addresses]..sort((a, b) => rank(a).compareTo(rank(b)));
  }

  /// Every address as a selectable URL, so the user can pick if the first is
  /// wrong (for example a VPN interface that also holds an address).
  List<String> get candidateUrls {
    final urls = [
      for (final address in usableAddresses) 'http://$address:$httpPort',
    ];
    if (publicUrlIsReachable && !urls.contains(publicUrl)) urls.add(publicUrl);
    return urls;
  }

  /// Whether [publicUrl] is something another device on this network could use.
  ///
  /// This matters more than it looks: `PUBLIC_URL` is usually left at the Android
  /// emulator alias (`10.0.2.2`) or at `localhost`, and a phone can resolve
  /// neither. Trusting it blindly sends every real phone to an address that does
  /// not exist, which the user experiences as "the server does not work" while it
  /// runs fine on the desk next to them.
  ///
  /// So: only an address the server also advertised, or a genuine hostname (how
  /// a hosted server is normally reached), is offered.
  bool get publicUrlIsReachable {
    if (!publicUrl.startsWith('http://') && !publicUrl.startsWith('https://')) {
      return false;
    }
    final host = Uri.tryParse(publicUrl)?.host ?? '';
    if (host.isEmpty) return false;
    if (host == 'localhost' || host == '10.0.2.2' || host.startsWith('127.')) {
      return false;
    }
    if (addresses.contains(host)) return true;
    // Not an IPv4 literal, so treat it as a DNS name and trust it.
    return !RegExp(r'^\d{1,3}(\.\d{1,3}){3}$').hasMatch(host);
  }

  /// Best-guess base URL, used as the default when this server is accepted.
  String get suggestedUrl {
    if (publicUrlIsReachable) return publicUrl;
    if (usableAddresses.isEmpty) return publicUrl;
    return 'http://${usableAddresses.first}:$httpPort';
  }
}

/// Finds SecureChat servers on the local network via UDP broadcast.

/// Finds SecureChat servers on the local network via UDP broadcast.
///
/// The APK is distributed to arbitrary users, so no server address can be
/// compiled into it. Rather than making every user read an IP off a terminal and
/// type it into a settings screen, the app listens for the server's periodic
/// UDP announcement and offers what it finds.
///
/// This channel carries **public addresses only** - no keys, no user data, no
/// message content.
class ServerDiscovery {
  const ServerDiscovery._();

  /// Must match the server's `DISCOVERY_PORT`.
  static const int port = 41234;

  /// How long to listen before reporting what was found.
  static const Duration listenWindow = Duration(seconds: 4);

  /// A server must answer `/health` before it is offered, so a random device on
  /// the network cannot masquerade as a SecureChat server.
  static const Duration probeTimeout = Duration(seconds: 4);

  /// Send a probe, then listen for announcements and replies.
  ///
  /// Returns every server heard from. Never throws: discovery is an accelerator,
  /// and a failure must leave the user with manual entry rather than an error.
  static Future<List<DiscoveredServer>> scan() async {
    final found = <String, DiscoveredServer>{};
    final completer = Completer<void>();
    Timer? window;
    RawDatagramSocket? socket;

    void finish() {
      if (!completer.isCompleted) completer.complete();
    }

    try {
      socket = await RawDatagramSocket.bind(
        InternetAddress.anyIPv4,
        0,
        reuseAddress: true,
      );
      socket.broadcastEnabled = true;

      window = Timer(listenWindow, finish);

      socket.listen((event) {
        if (event != RawSocketEvent.read) return;
        final datagram = socket!.receive();
        if (datagram == null) return;
        final parsed = _parse(datagram.data);
        if (parsed == null) return;
        // Dedupe on the advertised set, so a server seen on both the global and
        // the directed broadcast is still offered only once.
        found['${parsed.httpPort}|${parsed.addresses.join()}'] = parsed;
      });

      // Ask actively as well as listening passively. The server answers a probe
      // directly, which succeeds on networks that filter broadcast.
      await sendProbe(socket);
    } catch (_) {
      finish();
    }

    await completer.future;
    window?.cancel();
    _closeQuietly(socket);

    return found.values.toList(growable: false);
  }

  /// Send one probe and wait briefly for a direct reply.
  ///
  /// Cheaper than [scan] when the app only needs to know whether any server is
  /// out there, and the fallback when announcements never arrived.
  static Future<DiscoveredServer?> probe() async {
    RawDatagramSocket? socket;
    try {
      socket = await RawDatagramSocket.bind(
        InternetAddress.anyIPv4,
        0,
        reuseAddress: true,
      );
      socket.broadcastEnabled = true;

      final found = Completer<DiscoveredServer?>();

      socket.listen((event) {
        if (event != RawSocketEvent.read) return;
        final datagram = socket!.receive();
        if (datagram == null) return;
        final parsed = _parse(datagram.data);
        if (parsed != null && !found.isCompleted) found.complete(parsed);
      });

      Timer(probeTimeout, () {
        if (!found.isCompleted) found.complete(null);
      });

      await sendProbe(socket);
      return await found.future;
    } catch (_) {
      return null;
    } finally {
      _closeQuietly(socket);
    }
  }

  /// Validate that a base URL really is a SecureChat server.
  ///
  /// A discovered or hand-typed address is only usable if `/health` answers, so
  /// the user is never told "connected" to something that is not a server.
  static Future<bool> isSecureChatServer(String baseUrl) async {
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 4);
    try {
      final request = await client
          .getUrl(Uri.parse('$baseUrl/health'))
          .timeout(const Duration(seconds: 4));
      final response = await request.close().timeout(const Duration(seconds: 4));
      if (response.statusCode != 200) return false;
      final body = await response.transform(utf8.decoder).join();
      // A SecureChat server names itself. Without that check, any other service
      // holding the port - a leftover dev server from another project is the
      // classic case - looks like "our" server, and the user then gets a
      // meaningless sign-in error instead of being told the address is wrong.
      // The older payload (status + db) is still accepted so an app newer than
      // the server keeps working.
      if (RegExp('"service"\\s*:\\s*"securechat"').hasMatch(body)) return true;
      return body.contains('"status"') && body.contains('"db"');
    } catch (_) {
      return false;
    } finally {
      client.close(force: true);
    }
  }

  /// Broadcast the probe to the global address and to every local subnet.
  ///
  /// Sending to both matters: some access points drop the global broadcast but
  /// forward the directed one, and some do the opposite.
  static Future<void> sendProbe(RawDatagramSocket socket) async {
    final probe = utf8.encode('SECURECHAT/1 DISCOVER');
    for (final target in await broadcastTargets()) {
      try {
        socket.send(probe, InternetAddress(target), port);
      } catch (_) {
        // One unreachable target must not stop the others.
      }
    }
  }

  /// Broadcast addresses for every local interface, plus the global one.
  static Future<List<String>> broadcastTargets() async {
    final targets = <String>{'255.255.255.255'};
    try {
      for (final interface
          in await NetworkInterface.list(type: InternetAddressType.IPv4)) {
        for (final address in interface.addresses) {
          final parts = address.address.split('.');
          if (parts.length == 4) {
            targets.add('${parts[0]}.${parts[1]}.${parts[2]}.255');
          }
        }
      }
    } catch (_) {
      // Interface enumeration is best-effort; the global broadcast still goes.
    }
    return targets.toList(growable: false);
  }

  /// Parse an announcement. Anything unrecognised is ignored, so a stray UDP
  /// packet on this port cannot influence the app.
  static DiscoveredServer? _parse(List<int> data) {
    try {
      final json = jsonDecode(utf8.decode(data));
      if (json is! Map) return null;
      if (json['service'] != 'securechat') return null;
      final httpPort = json['httpPort'];
      if (httpPort is! int) return null;
      final raw = json['addresses'];
      if (raw is! List) return null;
      final addresses = raw
          .map((e) => '$e')
          .where((e) => RegExp(r'^\d{1,3}(\.\d{1,3}){3}$').hasMatch(e))
          .toList();
      if (addresses.isEmpty) return null;
      return DiscoveredServer(
        name: '${json['name'] ?? 'SecureChat server'}',
        addresses: addresses,
        httpPort: httpPort,
        publicUrl: '${json['publicUrl'] ?? ''}',
      );
    } catch (_) {
      return null;
    }
  }

  static void _closeQuietly(RawDatagramSocket? socket) {
    try {
      socket?.close();
    } catch (_) {
      // Already closed.
    }
  }
}
