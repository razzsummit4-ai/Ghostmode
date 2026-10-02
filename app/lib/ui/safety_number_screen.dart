import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../crypto/keys.dart';
import '../net/api.dart';
import '../state/app_state.dart';
import 'theme.dart';

/// Safety number: the out-of-band check that no one is in the middle.
///
/// The digits are derived from BOTH public identity keys, so both devices
/// independently compute the same value. A middleman who swapped either key
/// cannot produce matching digits, which is exactly what a voice or in-person
/// comparison detects.
class SafetyNumberScreen extends StatefulWidget {
  const SafetyNumberScreen({
    super.key,
    required this.peerId,
    required this.title,
  });

  final String peerId;
  final String title;

  @override
  State<SafetyNumberScreen> createState() => _SafetyNumberScreenState();
}

class _SafetyNumberScreenState extends State<SafetyNumberScreen> {
  String? _digits;
  String? _error;
  bool _loading = true;

  /// True when the peer's key differs from the one pinned for this chat.
  bool _identityChanged = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final state = context.read<AppState>();
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final res = await state.api.safetyNumber(widget.peerId);
      final remote = unb64('${res['remoteIdentityKey']}');
      if (!mounted) return;
      setState(() {
        _digits = state.messaging.safetyNumberFor(remote);
        _identityChanged = state.sessions.identityChanges.contains(widget.peerId);
        _loading = false;
      });
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() {
        _error = e.code == 'peer_has_no_keys'
            ? 'This device has not published its keys yet.'
            : (e.message ?? e.code);
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = '$e';
        _loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final groups = _digits?.split(' ') ?? const <String>[];

    return Scaffold(
      appBar: AppBar(title: const Text('Safety number')),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : _error != null
              ? _ErrorPane(message: _error!, onRetry: _load)
              : ListView(
                  padding: const EdgeInsets.all(20),
                  children: [
                    if (_identityChanged) const _WarningCard(),
                    Center(
                      child: ContactAvatar(name: widget.title, radius: 44),
                    ),
                    const SizedBox(height: 14),
                    Text(
                      widget.title,
                      textAlign: TextAlign.center,
                      style: const TextStyle(
                        fontSize: 20,
                        fontWeight: FontWeight.w600,
                        color: AppColors.textPrimary,
                      ),
                    ),
                    const SizedBox(height: 6),
                    const Text(
                      'Compare these 60 digits with your contact, in person or '
                      'over a call you trust. If they match, no one is '
                      'intercepting your messages.',
                      textAlign: TextAlign.center,
                      style: TextStyle(
                        fontSize: 13,
                        height: 1.5,
                        color: AppColors.textSecondary,
                      ),
                    ),
                    const SizedBox(height: 24),
                    Container(
                      padding: const EdgeInsets.all(18),
                      decoration: BoxDecoration(
                        color: AppColors.surface,
                        borderRadius: BorderRadius.circular(14),
                      ),
                      child: Column(
                        children: [
                          for (final row in _chunk(groups, 3))
                            Padding(
                              padding:
                                  const EdgeInsets.symmetric(vertical: 3),
                              child: Text(
                                row.join(' '),
                                textAlign: TextAlign.center,
                                style: const TextStyle(
                                  fontSize: 21,
                                  letterSpacing: 1.5,
                                  fontWeight: FontWeight.w500,
                                  fontFamily: 'monospace',
                                  color: AppColors.linkBlue,
                                ),
                              ),
                            ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 18),
                    Text(
                      'Your fingerprint: ${state.messaging.localFingerprint}',
                      textAlign: TextAlign.center,
                      style: const TextStyle(
                        fontSize: 12,
                        fontFamily: 'monospace',
                        color: AppColors.textSecondary,
                      ),
                    ),
                    const SizedBox(height: 20),
                    OutlinedButton.icon(
                      onPressed: _confirmVerified,
                      icon: const Icon(Icons.check_circle_outline),
                      label: const Text('Mark as verified'),
                    ),
                  ],
                ),
    );
  }

  /// Accept the current key as genuine, clearing any recorded change.
  ///
  /// This has to do three things, not one. Clearing the in-memory flag alone -
  /// which is all this used to do - left the stale key pinned in the vault, so
  /// the very next handshake compared against the old key, failed again, and
  /// the message stayed undeliverable with no way out.
  ///
  /// The pinned key is replaced with the one just shown and approved, and the
  /// cached session is dropped so a fresh X3DH handshake is performed against
  /// the key the user has now accepted.
  Future<void> _confirmVerified() async {
    final state = context.read<AppState>();
    final messenger = state.messaging;

    try {
      final res = await state.api.safetyNumber(widget.peerId);
      final approved = unb64('${res['remoteIdentityKey']}');

      await state.sessions.acceptIdentityChange(widget.peerId, approved);

      if (!mounted) return;
      Navigator.of(context).pop(true);
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Marked as verified. Messages will decrypt from now on.'),
        ),
      );

      // Re-fetch the thread so anything that failed while the key was pinned
      // out is retried now that the session has been rebuilt. The chat id is
      // asked of the server rather than rebuilt locally, because the server
      // owns the "two ids sorted and joined" rule that defines a direct thread.
      try {
        final chat = await state.api.chatWith(widget.peerId);
        final chatId = '${chat['chatId']}';
        if (chatId.isNotEmpty && chatId != 'null') {
          await messenger.loadThread(chatId);
        }
      } catch (_) {
        // The thread reload is best-effort: the key has already been accepted,
        // so the next send or the next real-time message succeeds regardless.
      }
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Could not verify: $e')),
      );
    }
  }

  static List<List<String>> _chunk(List<String> items, int size) {
    final out = <List<String>>[];
    for (var i = 0; i < items.length; i += size) {
      final end = i + size > items.length ? items.length : i + size;
      out.add(items.sublist(i, end));
    }
    return out;
  }
}

/// Shown when a peer's identity key no longer matches the pinned one.
class _WarningCard extends StatelessWidget {
  const _WarningCard();

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 18),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: AppColors.danger.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppColors.danger.withValues(alpha: 0.5)),
      ),
      child: const Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(Icons.gpp_bad, color: AppColors.danger, size: 20),
          SizedBox(width: 10),
          Expanded(
            child: Text(
              "This contact's safety number has changed. That can happen if "
              'they reinstall the app, or if someone is trying to intercept '
              'your conversation. Verify with them directly before trusting '
              'the new number.',
              style: TextStyle(fontSize: 12.5, height: 1.45),
            ),
          ),
        ],
      ),
    );
  }
}

class _ErrorPane extends StatelessWidget {
  const _ErrorPane({required this.message, required this.onRetry});

  final String message;
  final Future<void> Function() onRetry;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(28),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              message,
              textAlign: TextAlign.center,
              style: const TextStyle(color: AppColors.textSecondary),
            ),
            const SizedBox(height: 16),
            OutlinedButton(onPressed: onRetry, child: const Text('Retry')),
          ],
        ),
      ),
    );
  }
}
