/// Application configuration.
///
/// The server address is a **runtime** value rather than a compile-time
/// constant, so one APK works for everyone: a tester pointing at their laptop
/// on the LAN, a family running a server at home, and a production install
/// behind a domain all use the same binary.
///
/// It is seeded from `--dart-define=API_BASE_URL` and can be overridden from
/// Settings. The override is persisted, so a user configures the server once.
class AppConfig {
  /// Seed address, fixed when the APK was built.
  static const String compiledDefaultUrl = String.fromEnvironment(
    'API_BASE_URL',
    defaultValue: 'http://10.0.2.2:4000',
  );

  /// The address this install actually talks to. Mutable: [AppState] sets it
  /// from stored preferences at startup, and Settings can change it.
  static String apiBaseUrl = compiledDefaultUrl;

  static const appName = 'SecureChat';

  /// How many one-time pre-keys a fresh install publishes.
  ///
  /// The Signal recommendation is 100; the client tops this pool back up
  /// whenever the server reports it running low.
  static const initialPreKeyCount = 100;

  /// Pre-key count below which the client replenishes.
  static const preKeyLowWatermark = 20;

  static const requestTimeout = Duration(seconds: 20);

  /// Normalise whatever the user typed into a usable base URL.
  ///
  /// Accepts `192.168.0.100:4000` and `chat.example.com` by supplying the
  /// scheme and any trailing slash, which is the difference between a
  /// confusing error and a working app for a non-expert.
  static String normaliseUrl(String input) {
    var value = input.trim();
    if (value.isEmpty) return compiledDefaultUrl;

    if (!value.startsWith('http://') && !value.startsWith('https://')) {
      value = 'http://$value';
    }
    while (value.endsWith('/')) {
      value = value.substring(0, value.length - 1);
    }
    return value;
  }

  /// True when the address sends traffic in the clear.
  ///
  /// Message CONTENT is end-to-end encrypted regardless, so cleartext exposes
  /// only metadata (who talked to whom, when). The UI surfaces this so a user
  /// on plain HTTP knows what they are accepting.
  static bool get usesCleartext => apiBaseUrl.startsWith('http://');
}


