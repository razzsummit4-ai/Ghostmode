import 'package:flutter/services.dart';

/// Controls the platform's secure-window flag.
///
/// On Android this sets `FLAG_SECURE`, which makes the system refuse to render
/// the window into a screenshot or into the recent-apps thumbnail. The result
/// is a black image rather than a readable copy of a conversation.
///
/// This is prevention rather than detection: there is no callback to react to
/// because the screenshot never succeeds in the first place.
class SecureWindow {
  const SecureWindow._();

  static const _channel = MethodChannel('securechat/secure_window');

  /// Enable or disable screenshot blocking. A missing platform implementation
  /// is treated as a no-op so the app still runs on unsupported targets.
  static Future<void> setSecure(bool enabled) async {
    try {
      await _channel.invokeMethod<void>('setSecure', {'enabled': enabled});
    } on PlatformException {
      // Non-Android platform, or the channel is not registered. Screenshot
      // blocking is a hardening measure, not a correctness requirement, so a
      // failure here must not break the screen.
    } on MissingPluginException {
      // Same reasoning: no native side on this platform.
    }
  }
}
