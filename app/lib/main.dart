import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import 'core/config.dart';
import 'state/app_state.dart';
import 'ui/chat_list_screen.dart';
import 'ui/login_screen.dart';
import 'ui/theme.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Portrait only: a chat UI that reflows under rotation is a distraction, and
  // a locked orientation keeps the secure window predictable.
  await SystemChrome.setPreferredOrientations([DeviceOrientation.portraitUp]);

  final state = AppState();
  // Restore the token, the key vault and the screenshot preference before the
  // first frame, so the router never flashes the wrong screen.
  await state.bootstrap();

  runApp(SecureChatApp(state: state));
}

class SecureChatApp extends StatelessWidget {
  const SecureChatApp({super.key, required this.state});

  final AppState state;

  @override
  Widget build(BuildContext context) {
    return ChangeNotifierProvider<AppState>.value(
      value: state,
      child: MaterialApp(
        title: AppConfig.appName,
        debugShowCheckedModeBanner: false,
        theme: buildSecureDarkTheme(),
        home: const _RootRouter(),
      ),
    );
  }
}

/// Chooses the screen from the app's lifecycle phase.
///
/// The routing rule is the security rule: a device that has not published its
/// key bundle is never shown a chat screen, because it could not encrypt
/// anything it sent from there.
class _RootRouter extends StatelessWidget {
  const _RootRouter();

  @override
  Widget build(BuildContext context) {
    final phase = context.select<AppState, AppPhase>((s) => s.phase);

    return AnimatedSwitcher(
      duration: const Duration(milliseconds: 220),
      child: switch (phase) {
        AppPhase.booting => const _SplashScreen(key: ValueKey('splash')),
        AppPhase.signedOut => const LoginScreen(key: ValueKey('login')),
        AppPhase.generatingKeys => const _KeyGenScreen(key: ValueKey('keys')),
        AppPhase.ready => const ChatListScreen(key: ValueKey('chats')),
      },
    );
  }
}

/// Shown for the moment it takes to read the Keystore.
class _SplashScreen extends StatelessWidget {
  const _SplashScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return const Scaffold(
      body: Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.lock, size: 46, color: AppColors.accent),
            SizedBox(height: 18),
            Text(
              'SecureChat',
              style: TextStyle(
                fontSize: 20,
                fontWeight: FontWeight.w600,
                color: AppColors.textPrimary,
              ),
            ),
            SizedBox(height: 22),
            SizedBox(
              height: 22,
              width: 22,
              child: CircularProgressIndicator(strokeWidth: 2),
            ),
          ],
        ),
      ),
    );
  }
}

/// Shown while the first key identity is generated and published.
class _KeyGenScreen extends StatelessWidget {
  const _KeyGenScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final error = context.select<AppState, String?>((s) => s.lastError);

    return Scaffold(
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.vpn_key, size: 46, color: AppColors.accent),
              const SizedBox(height: 20),
              const Text(
                'Securing this device',
                style: TextStyle(
                  fontSize: 19,
                  fontWeight: FontWeight.w600,
                  color: AppColors.textPrimary,
                ),
              ),
              const SizedBox(height: 10),
              const Text(
                'Generating your identity key, a signed pre-key and 100 '
                'one-time pre-keys. The private halves are written to this '
                "device's hardware keystore and never leave it.",
                textAlign: TextAlign.center,
                style: TextStyle(
                  fontSize: 13.5,
                  height: 1.5,
                  color: AppColors.textSecondary,
                ),
              ),
              const SizedBox(height: 26),
              const SizedBox(
                height: 22,
                width: 22,
                child: CircularProgressIndicator(strokeWidth: 2),
              ),
              if (error != null) ...[
                const SizedBox(height: 18),
                Text(
                  error,
                  textAlign: TextAlign.center,
                  style: const TextStyle(
                    fontSize: 12.5,
                    color: AppColors.danger,
                  ),
                ),
                const SizedBox(height: 12),
                OutlinedButton(
                  onPressed: () => context.read<AppState>().bootstrap(),
                  child: const Text('Retry'),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }
}
