import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../core/config.dart';
import '../state/app_state.dart';
import 'server_picker_screen.dart';
import 'theme.dart';

/// Account, key and privacy settings.
class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();

    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: ListView(
        children: [
          _Header(
            name: state.displayName ?? 'You',
            subtitle: state.phone ?? '',
            fingerprint: state.messaging.localFingerprint,
          ),
          const SizedBox(height: 8),
          const _SectionLabel('Encryption'),
          ListTile(
            leading: const Icon(Icons.fingerprint),
            title: const Text('My identity fingerprint'),
            subtitle: Text(
              state.messaging.localFingerprint,
              style: const TextStyle(
                fontFamily: 'monospace',
                fontSize: 12.5,
              ),
            ),
          ),
          ListTile(
            leading: const Icon(Icons.key_outlined),
            title: const Text('Pre-keys available'),
            subtitle: Text(
              '${state.preKeysLeft} one-time keys reserved for incoming '
              'handshakes',
              style: const TextStyle(fontSize: 12.5),
            ),
            trailing: state.preKeysLeft < AppConfig.preKeyLowWatermark
                ? const StatusPill(
                    label: 'low',
                    color: AppColors.warning,
                    icon: Icons.warning_amber,
                  )
                : const StatusPill(
                    label: 'healthy',
                    color: AppColors.accent,
                    icon: Icons.check,
                  ),
          ),
          const Divider(),
          const _SectionLabel('Server'),
          ListTile(
            leading: Icon(
              Icons.dns_outlined,
              color: AppConfig.usesCleartext ? AppColors.warning : null,
            ),
            title: const Text('Server address'),
            subtitle: Text(
              AppConfig.apiBaseUrl,
              style: TextStyle(
                fontSize: 12.5,
                fontFamily: 'monospace',
                color: AppConfig.usesCleartext
                    ? AppColors.warning
                    : AppColors.textSecondary,
              ),
            ),
            trailing: AppConfig.usesCleartext
                ? const StatusPill(
                    label: 'no TLS',
                    color: AppColors.warning,
                    icon: Icons.lock_open,
                  )
                : const StatusPill(
                    label: 'https',
                    color: AppColors.accent,
                    icon: Icons.lock,
                  ),
            onTap: () => Navigator.of(context).push(
              MaterialPageRoute(builder: (_) => const ServerPickerScreen()),
            ),
          ),
          if (AppConfig.usesCleartext)
            const Padding(
              padding: EdgeInsets.fromLTRB(16, 0, 16, 8),
              child: Text(
                'Traffic to this server is not encrypted in transit. Messages '
                'remain end-to-end encrypted, so only metadata is exposed. Use '
                'https for anything beyond a trusted network.',
                style: TextStyle(
                  fontSize: 12,
                  height: 1.45,
                  color: AppColors.warning,
                ),
              ),
            ),
          const Divider(),
          const _SectionLabel('Privacy'),
          SwitchListTile(
            secondary: const Icon(Icons.no_photography_outlined),
            title: const Text('Block screenshots'),
            subtitle: const Text(
              'Applies the platform secure-window flag, so a screenshot comes '
              'out blank instead of copying your conversation.',
              style: TextStyle(fontSize: 12.5),
            ),
            value: state.blockScreenshots,
            onChanged: state.busy ? null : state.setBlockScreenshots,
          ),
          const Divider(),
          const _SectionLabel('Danger zone'),
          ListTile(
            leading: const Icon(Icons.autorenew, color: AppColors.warning),
            title: const Text(
              'Rotate identity keys',
              style: TextStyle(color: AppColors.warning),
            ),
            subtitle: const Text(
              "Destroys this device's keys and generates a new identity. "
              'Messages already sent to you become permanently unreadable, '
              'and every contact must re-verify your safety number.',
              style: TextStyle(fontSize: 12.5, height: 1.4),
            ),
            onTap: state.busy ? null : () => _confirmRegenerate(context),
          ),
          ListTile(
            leading: const Icon(Icons.logout, color: AppColors.danger),
            title: const Text(
              'Sign out and erase keys',
              style: TextStyle(color: AppColors.danger),
            ),
            subtitle: const Text(
              'Wipes every key held on this device.',
              style: TextStyle(fontSize: 12.5),
            ),
            onTap: () => _confirmLogout(context),
          ),
          const SizedBox(height: 24),
          Center(
            child: Text(
              'SecureChat 1.0.0',
              style: const TextStyle(
                fontSize: 11,
                color: AppColors.textSecondary,
              ),
            ),
          ),
          const SizedBox(height: 24),
        ],
      ),
    );
  }

  Future<void> _confirmRegenerate(BuildContext context) async {
    final state = context.read<AppState>();
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Rotate identity keys?'),
        content: const Text(
          'Your current identity and all ratchet sessions on this device will '
          'be erased.\n\n'
          '• Messages already sent to you can never be read again.\n'
          '• Contacts will see your safety number change.\n'
          '• Anyone holding your old public key stops reaching you.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            style: FilledButton.styleFrom(backgroundColor: AppColors.danger),
            child: const Text('Rotate'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    await state.regenerateKeys();
    if (!context.mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(state.lastError ?? 'New identity generated.')),
    );
  }

  Future<void> _confirmLogout(BuildContext context) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Sign out?'),
        content: const Text(
          'Every key on this device will be erased. You will need to verify '
          'your phone number again to sign back in.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            style: FilledButton.styleFrom(backgroundColor: AppColors.danger),
            child: const Text('Sign out'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    await context.read<AppState>().logout();
  }
}

class _Header extends StatelessWidget {
  const _Header({
    required this.name,
    required this.subtitle,
    required this.fingerprint,
  });

  final String name;
  final String subtitle;
  final String fingerprint;

  @override
  Widget build(BuildContext context) {
    return Container(
      color: AppColors.appBar,
      padding: const EdgeInsets.all(18),
      child: Row(
        children: [
          ContactAvatar(name: name, radius: 30),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  name,
                  style: const TextStyle(
                    fontSize: 19,
                    fontWeight: FontWeight.w600,
                    color: AppColors.textPrimary,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  subtitle,
                  style: const TextStyle(
                    fontSize: 13,
                    color: AppColors.textSecondary,
                  ),
                ),
                const SizedBox(height: 6),
                StatusPill(
                  label: fingerprint,
                  color: AppColors.accent,
                  icon: Icons.fingerprint,
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _SectionLabel extends StatelessWidget {
  const _SectionLabel(this.text);

  final String text;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 14, 16, 6),
      child: Text(
        text.toUpperCase(),
        style: const TextStyle(
          fontSize: 11.5,
          fontWeight: FontWeight.w600,
          letterSpacing: 0.8,
          color: AppColors.accent,
        ),
      ),
    );
  }
}
