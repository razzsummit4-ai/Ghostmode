import 'package:flutter_test/flutter_test.dart';
import 'package:securechat/core/config.dart';
import 'package:securechat/net/discovery.dart';

/// Which address the app offers is the difference between a phone that signs in
/// and a phone that reports the server as unreachable, so these choices are
/// worth pinning down.
DiscoveredServer _server({
  List<String> addresses = const ['192.168.0.100'],
  int httpPort = 4000,
  String publicUrl = '',
}) =>
    DiscoveredServer(
      name: 'SecureChat server',
      addresses: addresses,
      httpPort: httpPort,
      publicUrl: publicUrl,
    );

void main() {
  group('normaliseUrl', () {
    // The bug that made a hosted server unusable: a bare hostname became
    // http://, which the server answers with a 301 to https that this client
    // does not follow, so every probe failed and the app said "cannot reach".
    test('defaults a bare public hostname to https', () {
      expect(AppConfig.normaliseUrl('ghostmode.onrender.com'),
          'https://ghostmode.onrender.com');
      expect(AppConfig.normaliseUrl('chat.example.com'), 'https://chat.example.com');
    });

    // A self-hosted server on a home network has no certificate, so these must
    // keep the http default or the LAN setup that already works would break.
    test('keeps http for private LAN addresses', () {
      expect(AppConfig.normaliseUrl('192.168.0.100:4000'), 'http://192.168.0.100:4000');
      expect(AppConfig.normaliseUrl('10.0.2.2:4000'), 'http://10.0.2.2:4000');
      expect(AppConfig.normaliseUrl('172.20.10.4:4000'), 'http://172.20.10.4:4000');
      expect(AppConfig.normaliseUrl('localhost:4000'), 'http://localhost:4000');
      expect(AppConfig.normaliseUrl('myserver.local'), 'http://myserver.local');
    });

    test('never overrides a scheme the user typed', () {
      expect(AppConfig.normaliseUrl('http://192.168.1.5:4000'), 'http://192.168.1.5:4000');
      expect(AppConfig.normaliseUrl('https://chat.example.com'),
          'https://chat.example.com');
    });

    test('trims whitespace and trailing slashes', () {
      expect(AppConfig.normaliseUrl('  https://x.com/  '), 'https://x.com');
      expect(AppConfig.normaliseUrl('https://x.com///'), 'https://x.com');
    });
  });

  group('suggestedUrl', () {
    test('ignores the Android emulator alias, which no phone can resolve', () {
      // The server's PUBLIC_URL default. Advertising it sends every real device
      // to an address that only exists inside the emulator.
      final server = _server(publicUrl: 'http://10.0.2.2:4000');
      expect(server.suggestedUrl, 'http://192.168.0.100:4000');
    });

    test('ignores a loopback public URL for the same reason', () {
      expect(_server(publicUrl: 'http://localhost:4000').suggestedUrl,
          'http://192.168.0.100:4000');
      expect(_server(publicUrl: 'http://127.0.0.1:4000').suggestedUrl,
          'http://192.168.0.100:4000');
    });

    test('uses a public URL that matches an advertised address', () {
      final server = _server(
        addresses: const ['192.168.0.100', '172.20.10.4'],
        publicUrl: 'http://172.20.10.4:4000',
      );
      expect(server.suggestedUrl, 'http://172.20.10.4:4000');
    });

    test('trusts a real hostname, which is how a hosted server is reached', () {
      final server = _server(publicUrl: 'https://chat.example.com');
      expect(server.suggestedUrl, 'https://chat.example.com');
    });

    test('prefers a private range over a hotspot or link-local address', () {
      final server = _server(addresses: const ['169.254.9.9', '10.14.0.7']);
      expect(server.suggestedUrl, 'http://10.14.0.7:4000');
      expect(server.candidateUrls.first, 'http://10.14.0.7:4000');
      expect(server.candidateUrls.last, 'http://169.254.9.9:4000');
    });
  });

  group('candidateUrls', () {
    test('lists every advertised address so the user can override', () {
      final server = _server(addresses: const ['192.168.0.100'], httpPort: 4100);
      expect(server.candidateUrls, ['http://192.168.0.100:4100']);
    });

    test('appends a usable public URL without duplicating an address', () {
      final withHost = _server(publicUrl: 'https://chat.example.com');
      expect(withHost.candidateUrls.last, 'https://chat.example.com');

      final duplicate = _server(publicUrl: 'http://192.168.0.100:4000');
      expect(duplicate.candidateUrls, ['http://192.168.0.100:4000']);
    });
  });

  group('publicUrlIsReachable', () {
    test('rejects anything that is not a URL', () {
      expect(_server(publicUrl: '').publicUrlIsReachable, isFalse);
      expect(_server(publicUrl: '192.168.0.100:4000').publicUrlIsReachable,
          isFalse);
    });
  });
}
