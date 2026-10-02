import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../crypto/keys.dart';
import '../net/api.dart';
import '../state/app_state.dart';
import 'theme.dart';

/// Enter the verification code the other person created, to open a conversation
/// with them.
///
/// Nothing can be read or sent until this succeeds - the server refuses both,
/// so this gate is not decoration. The code is whatever that person shows in
/// their own profile and shares with you directly.
class VerifyPeerScreen extends StatefulWidget {
  const VerifyPeerScreen({
    super.key,
    required this.peerId,
    required this.peerName,
  });

  final String peerId;
  final String peerName;

  /// Returns true when the code was accepted, so the caller can reload.
  static Future<bool> open(
    BuildContext context, {
    required String peerId,
    required String peerName,
  }) async {
    final ok = await Navigator.of(context).push<bool>(
      MaterialPageRoute(
        builder: (_) => VerifyPeerScreen(peerId: peerId, peerName: peerName),
      ),
    );
    return ok ?? false;
  }

  @override
  State<VerifyPeerScreen> createState() => _VerifyPeerScreenState();
}

class _VerifyPeerScreenState extends State<VerifyPeerScreen> {
  final _controller = TextEditingController();
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    final code = _controller.text.trim();
    if (code.isEmpty) {
      setState(() => _error = 'Enter the code they gave you.');
      return;
    }

    final api = context.read<AppState>().api;
    setState(() {
      _busy = true;
      _error = null;
    });

    final state = context.read<AppState>();
      try {
        // The grant and the identity key come back together. Accepting the code is
        // the user vouching for this person, so the device must drop the key it
        // pinned before as well - otherwise the next send is refused by
        // _verifyPinnedIdentity and the message never leaves the device.
        final identityKey = await api.verifyWith(widget.peerId, code);
        if (identityKey != null && identityKey.isNotEmpty) {
          await state.sessions.acceptIdentityChange(widget.peerId, unb64(identityKey));
        }

      if (!mounted) return;
      Navigator.of(context).pop(true);
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() {
        _error = switch (e.code) {
          'verification_failed' =>
            'That code is not correct. Ask ${widget.peerName} for the code '
                'in their profile, then enter it exactly as they gave it.',
          'weak_verification_code' => e.message ?? e.code,
          _ => e.message ?? e.code,
        };
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
      appBar: AppBar(title: const Text('Verification required')),
      body: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          Text(
            'You cannot message ${widget.peerName} yet.',
            style: const TextStyle(
              fontSize: 17,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 10),
          const Text(
            'Ask them to open their profile and copy the verification code they '
            'created. Enter it below. Until you do, neither of you can read or '
            'send any messages.',
            style: TextStyle(
              fontSize: 14,
              height: 1.5,
              color: AppColors.textSecondary,
            ),
          ),
          const SizedBox(height: 24),
          TextField(
            controller: _controller,
            autofocus: true,
            textCapitalization: TextCapitalization.characters,
            keyboardType: TextInputType.visiblePassword,
            style: const TextStyle(
              fontSize: 22,
              letterSpacing: 3,
              fontFamily: 'monospace',
            ),
            inputFormatters: [
              // Only the characters a code can contain, so a stray symbol
              // cannot turn into a silent mismatch.
              FilteringTextInputFormatter.allow(RegExp('[A-Za-z0-9 -]')),
              LengthLimitingTextInputFormatter(20),
            ],
            decoration: const InputDecoration(
              hintText: 'XXXX-XXXX-XXXX',
              border: OutlineInputBorder(),
            ),
            onChanged: (_) {
              if (_error != null) setState(() => _error = null);
            },
            onSubmitted: (_) => _submit(),
          ),
          if (_error != null) ...[
            const SizedBox(height: 14),
            Text(
              _error!,
              style: const TextStyle(
                fontSize: 13,
                height: 1.45,
                color: AppColors.danger,
              ),
            ),
          ],
          const SizedBox(height: 22),
          FilledButton(
            onPressed: _busy ? null : _submit,
            child: Text(_busy ? 'Checking...' : 'Verify'),
          ),
        ],
      ),
    );
  }
}