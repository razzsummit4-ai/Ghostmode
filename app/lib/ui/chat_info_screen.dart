import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../state/app_state.dart';
import 'theme.dart';

/// Per-conversation details, including the disappearing-message timer.
class ChatInfoScreen extends StatefulWidget {
  const ChatInfoScreen({
    super.key,
    required this.chatId,
    required this.title,
    this.peerId,
    this.groupId,
    this.isGroup = false,
  });

  final String chatId;
  final String title;
  final String? peerId;
  final String? groupId;
  final bool isGroup;

  @override
  State<ChatInfoScreen> createState() => _ChatInfoScreenState();
}

class _ChatInfoScreenState extends State<ChatInfoScreen> {
  int _seconds = 0;
  bool _loading = true;
  bool _saving = false;

  /// Offered timers. Group timers are enforced server-side on the ciphertext;
  /// a per-chat timer is carried inside each message envelope.
  static const _options = <int, String>{
    0: 'Off',
    60: '1 minute',
    3600: '1 hour',
    86400: '1 day',
    604800: '1 week',
  };

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _load());
  }

  Future<void> _load() async {
    final state = context.read<AppState>();
    if (!widget.isGroup) {
      if (mounted) setState(() => _loading = false);
      return;
    }
    try {
      final res = await state.api.group(widget.groupId!);
      final value =
          ((res['group'] as Map?)?['disappearingMessagesSeconds'] as num?)
                  ?.toInt() ??
              0;
      if (!mounted) return;
      setState(() {
        _seconds = value;
        _loading = false;
      });
    } catch (_) {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _setTimer(int seconds) async {
    final state = context.read<AppState>();
    final previous = _seconds;
    setState(() {
      _seconds = seconds;
      _saving = true;
    });

    // The local summary drives the banner immediately.
    state.chats.summary(widget.chatId)?.disappearingMessagesSeconds = seconds;

    try {
      await state.api.updateGroup(
        widget.groupId!,
        disappearingMessagesSeconds: seconds,
      );
    } catch (_) {
      // Revert, so the UI never claims a policy the server is not enforcing.
      if (mounted) {
        state.chats.summary(widget.chatId)?.disappearingMessagesSeconds =
            previous;
        setState(() => _seconds = previous);
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Could not change the timer.')),
        );
      }
    }
    if (mounted) setState(() => _saving = false);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Chat info')),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : ListView(
              children: [
                Padding(
                  padding: const EdgeInsets.symmetric(vertical: 24),
                  child: Column(
                    children: [
                      ContactAvatar(
                        name: widget.isGroup
                            ? '# ${widget.title}'
                            : widget.title,
                        radius: 40,
                      ),
                      const SizedBox(height: 12),
                      Text(
                        widget.title,
                        style: const TextStyle(
                          fontSize: 20,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ],
                  ),
                ),
                EncryptionBanner(onTap: _noop),
                const SizedBox(height: 8),
                const _SectionHeader('DISAPPEARING MESSAGES'),
                if (widget.isGroup)
                  for (final entry in _options.entries)
                    RadioListTile<int>(
                      value: entry.key,
                      groupValue: _seconds,
                      onChanged: _saving
                          ? null
                          : (v) => v == null ? null : _setTimer(v),
                      title: Text(entry.value),
                      activeColor: AppColors.accent,
                    )
                else
                  const Padding(
                    padding: EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                    child: Text(
                      'Set the timer in the chat screen, or ask the sender to '
                      'use disappearing messages. It travels inside each '
                      'encrypted message, so the server only knows the deadline '
                      'it was told, not the content.',
                      style: TextStyle(
                        fontSize: 13,
                        height: 1.45,
                        color: AppColors.textSecondary,
                      ),
                    ),
                  ),
                const Divider(),
                const _SectionHeader('ENCRYPTION'),
                const ListTile(
                  leading: Icon(Icons.lock_outline),
                  title: Text('Double Ratchet (X25519 + AES-256-GCM)'),
                  subtitle: Text(
                    'Every message uses a fresh key derived from a chain that '
                    'advances on both sides, giving forward secrecy.',
                    style: TextStyle(fontSize: 12.5, height: 1.4),
                  ),
                ),
                const ListTile(
                  leading: Icon(Icons.cloud_off),
                  title: Text('Server is zero-knowledge'),
                  subtitle: Text(
                    'It stores ciphertext, IVs and public keys. It holds no '
                    'material that could decrypt your messages.',
                    style: TextStyle(fontSize: 12.5, height: 1.4),
                  ),
                ),
              ],
            ),
    );
  }

  void _noop() {}
}

class _SectionHeader extends StatelessWidget {
  const _SectionHeader(this.text);

  final String text;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 14, 16, 6),
      child: Text(
        text,
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
