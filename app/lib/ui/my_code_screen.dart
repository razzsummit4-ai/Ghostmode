import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../state/app_state.dart';
import 'theme.dart';

/// Create, show and rotate the code this account shares with people who want to
/// talk to it.
///
/// This replaces the old safety-number flow. There is no fingerprint to compare
/// and no "mark as verified" that only silenced a warning: the code is created
/// here, shared out of band, and the other person must enter it before either of
/// you can read or send anything.
class MyVerificationCodeScreen extends StatefulWidget {
  const MyVerificationCodeScreen({super.key});

  @override
  State<MyVerificationCodeScreen> createState() =>
      _MyVerificationCodeScreenState();
}

class _MyVerificationCodeScreenState extends State<MyVerificationCodeScreen> {
  String? _code;
  bool _loading = true;
  bool _busy = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final api = context.read<AppState>().api;
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final code = await api.myVerificationCode();
      if (!mounted) return;
      setState(() {
        _code = code;
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

  Future<void> _create({bool rotate = false}) async {
    final api = context.read<AppState>().api;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final code = await api.createVerificationCode(rotate: rotate);
      if (!mounted) return;
      setState(() {
        _code = code;
        _busy = false;
      });
      await Clipboard.setData(ClipboardData(text: code));
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Copied: $code')),
      );
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = '$e';
        _busy = false;
      });
    }
  }
@override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('My verification code')),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : ListView(
              padding: const EdgeInsets.all(20),
              children: [
                Text(
                  _code == null
                      ? 'You have no code yet.'
                      : 'Share this code with anyone you want to be able to '
                          'message you.',
                  style: const TextStyle(
                    fontSize: 14,
                    height: 1.5,
                    color: AppColors.textSecondary,
                  ),
                ),
                const SizedBox(height: 22),
                if (_code != null)
                  Container(
                    padding: const EdgeInsets.all(22),
                    decoration: BoxDecoration(
                      color: AppColors.surface,
                      borderRadius: BorderRadius.circular(14),
                      border: Border.all(color: AppColors.accent, width: 1.5),
                    ),
                    child: Column(
                      children: [
                        Text(
                          _code!,
                          textAlign: TextAlign.center,
                          style: const TextStyle(
                            fontSize: 24,
                            letterSpacing: 2,
                            fontWeight: FontWeight.w600,
                            fontFamily: 'monospace',
                            color: AppColors.accent,
                          ),
                        ),
                        const SizedBox(height: 14),
                        OutlinedButton.icon(
                          onPressed: _busy
                              ? null
                              : () async {
                                  await Clipboard.setData(
                                    ClipboardData(text: _code!),
                                  );
                                  if (!context.mounted) return;
                                  ScaffoldMessenger.of(context).showSnackBar(
                                    const SnackBar(
                                      content: Text('Code copied.'),
                                    ),
                                  );
                                },
                          icon: const Icon(Icons.copy, size: 18),
                          label: const Text('Copy'),
                        ),
                      ],
                    ),
                  ),
                if (_error != null) ...[
                  const SizedBox(height: 16),
                  Text(
                    _error!,
                    style: const TextStyle(
                      fontSize: 12.5,
                      color: AppColors.danger,
                    ),
                  ),
                ],
                const SizedBox(height: 24),
                FilledButton.icon(
                  onPressed: _busy ? null : () => _create(rotate: _code != null),
                  icon: Icon(
                    _code == null ? Icons.add : Icons.refresh,
                    size: 18,
                  ),
                  label: Text(_code == null ? 'Create my code' : 'Rotate my code'),
                ),
                if (_code != null) ...[
                  const SizedBox(height: 14),
                  const Text(
                    'Rotating replaces the old code. Anyone still using it will '
                    'no longer be able to open a conversation with you.',
                    style: TextStyle(
                      fontSize: 12.5,
                      height: 1.45,
                      color: AppColors.textSecondary,
                    ),
                  ),
                ],
              ],
            ),
    );
  }
}