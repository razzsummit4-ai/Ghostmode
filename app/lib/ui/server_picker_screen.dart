import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../core/config.dart';
import '../net/discovery.dart';
import '../state/app_state.dart';
import 'theme.dart';

/// Lets the user point the app at their SecureChat server.
///
/// The address is stored on the device, so a single APK serves everyone: a
/// tester on a LAN address, or a production install behind a domain. Without
/// this the app would be locked to whatever host was compiled in.
class ServerPickerScreen extends StatefulWidget {
  const ServerPickerScreen({super.key, this.showSuccessOnPop = true});

  /// Whether a successful save should be confirmed to the user.
  final bool showSuccessOnPop;

  @override
  State<ServerPickerScreen> createState() => _ServerPickerScreenState();
}

class _ServerPickerScreenState extends State<ServerPickerScreen> {
  late final TextEditingController _controller = TextEditingController(
    text: AppConfig.apiBaseUrl,
  );
  bool _testing = false;
  String? _result;
  bool _resultOk = false;

  /// Servers found by the last scan, rendered as one-tap choices.
  List<DiscoveredServer> _found = const [];

  /// Use a discovered server: fill the field so the user can see and confirm
  /// exactly what will be saved, rather than having it change silently.
  void _use(DiscoveredServer server) {
    setState(() {
      _controller.text = server.suggestedUrl;
      _found = const [];
      _result = null;
    });
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  /// Probe the typed address without committing to it.
  Future<void> _test() async {
    final state = context.read<AppState>();
    final candidate = AppConfig.normaliseUrl(_controller.text);

    setState(() {
      _testing = true;
      _result = null;
    });

    // Temporarily point the client at the candidate so the probe is honest.
    final previous = AppConfig.apiBaseUrl;
    AppConfig.apiBaseUrl = candidate;
    final res = await state.testServer();
    if (AppConfig.apiBaseUrl == candidate) {
      AppConfig.apiBaseUrl = previous;
    }

    if (!mounted) return;
    setState(() {
      _testing = false;
      _resultOk = res.ok;
      _result = res.detail;
    });
  }

  /// Look for servers on this Wi-Fi and list what answers.
  ///
  /// This is the path that works for someone who has never been told what an IP
  /// address is: the phone finds the server itself.
  Future<void> _discover() async {
    setState(() {
      _testing = true;
      _result = null;
      _found = const [];
    });

    final servers = await context.read<AppState>().discoverServers();
    if (!mounted) return;
    setState(() {
      _testing = false;
      _found = servers;
      _resultOk = servers.isNotEmpty;
      _result = servers.isEmpty
          ? 'No SecureChat server found on this network. Check the phone is on '
              'the same Wi-Fi as the computer running it, then try again.'
          : 'Found ${servers.length} server'
              '${servers.length == 1 ? '' : 's'}. Tap one to use it.';
    });
  }

  Future<void> _save() async {
    final state = context.read<AppState>();
    await state.setServerUrl(_controller.text);
    if (!mounted) return;
    Navigator.of(context).pop(true);
    if (widget.showSuccessOnPop) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Server set to ${state.serverUrl}')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final onCleartext = AppConfig.normaliseUrl(_controller.text)
        .startsWith('http://');

    return Scaffold(
      appBar: AppBar(title: const Text('Server address')),
      body: ListView(
        padding: const EdgeInsets.all(18),
        children: [
          const Text(
            'Where is your SecureChat server?',
            style: TextStyle(
              fontSize: 18,
              fontWeight: FontWeight.w600,
              color: AppColors.textPrimary,
            ),
          ),
          const SizedBox(height: 6),
          const Text(
            'Enter the address of the machine running the SecureChat backend. '
            'It is saved on this device only.',
            style: TextStyle(
              fontSize: 13.5,
              height: 1.45,
              color: AppColors.textSecondary,
            ),
          ),
          const SizedBox(height: 20),
          TextField(
            controller: _controller,
            keyboardType: TextInputType.url,
            autocorrect: false,
            style: const TextStyle(fontSize: 15),
            decoration: const InputDecoration(
              labelText: 'Server URL',
              hintText: 'http://192.168.0.100:4000',
              prefixIcon: Icon(Icons.dns_outlined, size: 20),
            ),
            onChanged: (_) => setState(() {}),
          ),
          const SizedBox(height: 10),
          const _Hint(
            icon: Icons.phone_android,
            text: 'On a phone, use your computer LAN address such as '
                '192.168.0.100:4000, not 10.0.2.2 — that one only works '
                'inside an emulator.',
          ),
          const _Hint(
            icon: Icons.public,
            text: 'For a hosted server use https://, for example '
                'https://chat.example.com.',
          ),
          if (onCleartext) ...[
            const SizedBox(height: 6),
            const _Hint(
              icon: Icons.lock_open,
              warn: true,
              text: 'This address is not encrypted in transit. Your messages '
                  'are still end-to-end encrypted, so only metadata such as who '
                  'is talking to whom would be visible. Prefer https outside a '
                  'trusted network.',
            ),
          ],
          const SizedBox(height: 20),
          if (_result != null) ...[
            _ResultBanner(message: _result!, ok: _resultOk),
            const SizedBox(height: 16),
          ],
          if (_found.isNotEmpty) ...[
            for (final server in _found) ...[
              _FoundServerTile(
                server: server,
                onTap: () => _use(server),
              ),
              const SizedBox(height: 8),
            ],
            const SizedBox(height: 8),
          ],
          OutlinedButton.icon(
            onPressed: _testing ? null : _discover,
            icon: _testing
                ? const SizedBox(
                    height: 16,
                    width: 16,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.wifi_find_outlined),
            label: const Text('Find servers on this Wi-Fi'),
          ),
          const SizedBox(height: 10),
          OutlinedButton.icon(
            onPressed: _testing ? null : _test,
            icon: _testing
                ? const SizedBox(
                    height: 16,
                    width: 16,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.wifi_tethering),
            label: const Text('Test connection'),
          ),
          const SizedBox(height: 10),
          FilledButton.icon(
            onPressed: _save,
            icon: const Icon(Icons.save_outlined),
            label: const Text('Save and continue'),
          ),
        ],
      ),
    );
  }
}

/// A server found on the network, offered as a single tap.
class _FoundServerTile extends StatelessWidget {
  const _FoundServerTile({required this.server, required this.onTap});

  final DiscoveredServer server;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return Material(
      color: AppColors.elevated,
      borderRadius: BorderRadius.circular(12),
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(12),
        child: Container(
          padding: const EdgeInsets.all(13),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: AppColors.accent.withValues(alpha: 0.4)),
          ),
          child: Row(
            children: [
              const Icon(Icons.dns_outlined, size: 19, color: AppColors.accent),
              const SizedBox(width: 11),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      server.name,
                      style: const TextStyle(
                        fontSize: 14,
                        fontWeight: FontWeight.w600,
                        color: AppColors.textPrimary,
                      ),
                    ),
                    const SizedBox(height: 3),
                    Text(
                      server.suggestedUrl,
                      style: const TextStyle(
                        fontSize: 12,
                        fontFamily: 'monospace',
                        color: AppColors.textSecondary,
                      ),
                    ),
                  ],
                ),
              ),
              const Icon(Icons.chevron_right, color: AppColors.textSecondary),
            ],
          ),
        ),
      ),
    );
  }
}

/// Feedback after a connection test.
class _ResultBanner extends StatelessWidget {
  const _ResultBanner({required this.message, required this.ok});

  final String message;
  final bool ok;

  @override
  Widget build(BuildContext context) {
    final color = ok ? AppColors.accent : AppColors.danger;
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: color.withValues(alpha: 0.45)),
      ),
      child: Row(
        children: [
          Icon(ok ? Icons.check_circle : Icons.error_outline, size: 18, color: color),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              message,
              style: const TextStyle(fontSize: 12.5, height: 1.4),
            ),
          ),
        ],
      ),
    );
  }
}

class _Hint extends StatelessWidget {
  const _Hint({required this.icon, required this.text, this.warn = false});

  final IconData icon;
  final String text;
  final bool warn;

  @override
  Widget build(BuildContext context) {
    final color = warn ? AppColors.warning : AppColors.textSecondary;
    return Padding(
      padding: const EdgeInsets.only(bottom: 8, right: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(icon, size: 15, color: color),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              text,
              style: TextStyle(fontSize: 12, height: 1.45, color: color),
            ),
          ),
        ],
      ),
    );
  }
}
