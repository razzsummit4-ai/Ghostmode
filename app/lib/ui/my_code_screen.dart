import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../net/api.dart';
import '../state/app_state.dart';
import 'theme.dart';

/// Characters a verification code may use.
///
/// The letters O and I, and the digits 0 and 1 are left out on purpose: they
/// are the pairs people confuse most when a code is read aloud or copied by
/// hand, and a code that survives being dictated is the whole point.
const verificationAlphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

/// How a stored verification code is grouped, e.g. `SUNS-HADE-2244`.
const verificationGroups = 3;
const verificationGroupLength = 4;

const _verificationLength = verificationGroups * verificationGroupLength;

/// Format 12 raw characters as `XXXX-XXXX-XXXX`.
String formatVerificationCode(String raw) {
  final buffer = StringBuffer();
  for (var i = 0; i < raw.length; i += verificationGroupLength) {
    if (i > 0) buffer.write('-');
    buffer.write(raw.substring(i, i + verificationGroupLength));
  }
  return buffer.toString();
}

/// Reduce whatever the owner typed to the canonical stored form.
///
/// Case, spaces and dashes are styling rather than part of the code, so
/// `sunshade 2244`, `SUNSHADE-2244` and `sunshade2244` are all one code.
///
/// Characters outside [verificationAlphabet] are REJECTED rather than dropped.
/// Dropping one would quietly shorten the code, so someone typing a word
/// containing an I or an O would get a different, shorter code back with no
/// explanation. This mirrors `canonicalise()` on the server, which is the
/// authority; this copy exists only so the field can show the stored form
/// before the round trip.
///
/// Throws [ArgumentError] if the result would not be exactly
/// `verificationGroups * verificationGroupLength` usable characters.
String canonicalVerificationCode(String input) {
  final raw = input.toUpperCase().replaceAll(RegExp('[^A-Z0-9]'), '');

  final bad = raw.split('').where((c) => !verificationAlphabet.contains(c));
  if (bad.isNotEmpty) {
    throw ArgumentError(
      'Cannot use ${bad.toSet().join(' ')}. The letters O and I, and the '
      'digits 0 and 1, are left out because they are too easily confused '
      'when a code is read aloud.',
    );
  }
  if (raw.length != _verificationLength) {
    throw ArgumentError('Use exactly $_verificationLength characters.');
  }
  return formatVerificationCode(raw);
}
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

  /// Live echo of the stored form while the owner types, and why an input is
  /// unusable. Both null until the field has something in it.
  String? _preview;
  String? _previewError;

  /// Non-null once the user starts typing their own, which replaces the
  /// "generate one for me" button.
  final _custom = TextEditingController();

  @override
  void dispose() {
    _custom.dispose();
    super.dispose();
  }

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
    final typed = _custom.text.trim();

    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      // When the user typed something, that becomes the code. Otherwise the
      // server generates one. Either way the server decides whether it is
      // usable and explains itself if not - the app never decides the rules.
      final code = await api.createVerificationCode(
        rotate: rotate,
        code: typed.isEmpty ? null : typed,
      );
      if (!mounted) return;
      setState(() {
        _code = code;
        _busy = false;
        _custom.clear();
        _preview = null;
        _previewError = null;
      });
      await Clipboard.setData(ClipboardData(text: code));
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Copied: $code')),
      );
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() {
        _error = e.code == 'weak_verification_code'
            ? (e.message ?? e.code)
            : '$e';
        _busy = false;
      });
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

                // Choosing your own is the default path: a code gets read
                // aloud and typed by hand, so a memorable one is easier to
                // convey than a generated one. Leaving this blank still works
                // and asks the server for one.
                TextField(
                  controller: _custom,
                  enabled: !_busy,
                  autocorrect: false,
                  textCapitalization: TextCapitalization.characters,
                  style: const TextStyle(
                    fontFamily: 'monospace',
                    letterSpacing: 1.5,
                    color: AppColors.accent,
                  ),
                  decoration: const InputDecoration(
                    labelText: 'Or choose your own',
                    hintText: '12 characters, A-Z and 2-9',
                    helperText: 'The letters O and I, and digits 0 and 1, '
                        'are not used - they are too easily confused when '
                        'read aloud.',
                    helperMaxLines: 3,
                    border: OutlineInputBorder(),
                  ),
                  onChanged: (value) {
                    // Show the stored form as it is typed, and refuse early
                    // with the same reason the server would give. The server
                    // still decides; this only avoids a pointless round trip.
                    setState(() {
                      _previewError = null;
                      final typed = value.trim();
                      if (typed.isNotEmpty) {
                        try {
                          _preview = canonicalVerificationCode(typed);
                        } on ArgumentError catch (e) {
                          _previewError = e.message?.toString();
                        }
                      }
                    });
                  },
                ),
                if (_preview != null || _previewError != null) ...[
                  const SizedBox(height: 8),
                  Text(
                    _preview ?? _previewError!,
                    style: TextStyle(
                      fontSize: 12.5,
                      fontFamily: _preview == null ? null : 'monospace',
                      letterSpacing: _preview == null ? 0 : 1.5,
                      color: _preview == null
                          ? AppColors.danger
                          : AppColors.accent,
                    ),
                  ),
                ],
                const SizedBox(height: 14),
                FilledButton.icon(
                  onPressed: _busy
                      ? null
                      : () => _create(rotate: _code != null),
                  icon: Icon(
                    _custom.text.trim().isEmpty
                        ? (_code == null ? Icons.add : Icons.refresh)
                        : Icons.check,
                    size: 18,
                  ),
                  label: Text(
                    _custom.text.trim().isNotEmpty
                        ? (_code == null
                            ? 'Use my code'
                            : 'Replace with my code')
                        : (_code == null
                            ? 'Create my code'
                            : 'Rotate my code'),
                  ),
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