import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../core/config.dart';
import '../state/app_state.dart';
import 'server_picker_screen.dart';
import 'theme.dart';

/// Sign in, or create an account, with a phone number and password.
///
/// A number can be registered exactly once. The screen checks that up front so
/// a user who already has an account is steered to the sign-in form instead of
/// filling in a sign-up the server will reject.
class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final _phoneController = TextEditingController();
  final _passwordController = TextEditingController();
  final _nameController = TextEditingController();
  final _phoneFocus = FocusNode();

  /// Sign-up and sign-in are distinct modes; there is no combined "continue".
  bool _registering = true;
  bool _obscure = true;
  bool _checking = false;

  /// Set when the server reports this number already has an account.
  bool? _alreadyRegistered;

  @override
  void initState() {
    super.initState();
    // Offer sign-up first, since a new user has no account yet.
    _registering = true;
  }

  @override
  void dispose() {
    _phoneController.dispose();
    _passwordController.dispose();
    _nameController.dispose();
    _phoneFocus.dispose();
    super.dispose();
  }

  /// Normalise toward E.164 so the server's normaliser sees one format.
  String _normalisedPhone() {
    final digits = _phoneController.text.replaceAll(RegExp(r'[^\d+]'), '');
    return digits.startsWith('+') ? digits : '+$digits';
  }

  void _setMode(bool registering) {
    setState(() {
      _registering = registering;
      _alreadyRegistered = null;
      _passwordController.clear();
    });
  }

  /// Ask the server whether this number is taken, and steer accordingly.
  ///
  /// This is a convenience, not a security control: the server enforces
  /// uniqueness regardless of what the client checked.
  Future<void> _checkNumber() async {
    final phone = _normalisedPhone();
    if (phone.length < 8) return;
    final state = context.read<AppState>();
    setState(() => _checking = true);
    try {
      final registered = await state.isRegistered(phone);
      if (!mounted) return;
      setState(() {
        _alreadyRegistered = registered;
        if (registered) _registering = false;
      });
    } catch (_) {
      // Offline or unknown: leave the mode alone and let submit decide.
    } finally {
      if (mounted) setState(() => _checking = false);
    }
  }

  String? _validate() {
    if (_normalisedPhone().length < 8) {
      return 'Enter your mobile number with the country code.';
    }
    if (_passwordController.text.isEmpty) return 'Enter a password.';
    if (_registering && _passwordController.text.length < 8) {
      return 'Password must be at least 8 characters.';
    }
    return null;
  }

  Future<void> _submit() async {
    final problem = _validate();
    if (problem != null) {
      _toast(problem);
      return;
    }

    final state = context.read<AppState>();
    final phone = _normalisedPhone();
    final password = _passwordController.text;
    final name = _nameController.text.trim();

    final ok = _registering
        ? await state.register(
            phone,
            password,
            displayName: name.isEmpty ? null : name,
          )
        : await state.login(
            phone,
            password,
            displayName: name.isEmpty ? null : name,
          );

    if (!mounted) return;
    if (ok) return;

    final message = state.lastError ?? 'Something went wrong. Try again.';
    _toast(message);
    // If the number is already taken, switch to the right form rather than
    // making the user work out why their sign-up failed.
    if (message.toLowerCase().contains('already exists')) {
      setState(() {
        _registering = false;
        _alreadyRegistered = true;
      });
    }
    // A network failure, or an address that answers but is not ours, is not
    // fixable by retyping credentials. Offer the one action that does help
    // instead of leaving the user to guess.
    if (message.contains('not a SecureChat server') ||
        message.toLowerCase().contains('cannot reach the server')) {
      await _promptFixServer();
    }
    _passwordController.clear();
  }

  /// Explain, in place, that the address is the problem and offer to fix it.
  Future<void> _promptFixServer() async {
    // Tri-state: 0 cancel, 1 discover, 2 type an address.
    final choice = await showDialog<int>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('Cannot reach the server'),
        content: Text(
          'The app is trying to use\n${AppConfig.apiBaseUrl}\n\n'
          'Make sure this phone is on the same Wi-Fi as the server. You can let '
          'the app look for it, or type the address yourself.',
          style: const TextStyle(fontSize: 13.5, height: 1.45),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(0),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(1),
            child: const Text('Find server'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(dialogContext).pop(2),
            child: const Text('Enter address'),
          ),
        ],
      ),
    );
    if (!mounted || choice == null || choice == 0) return;

    if (choice == 2) {
      await Navigator.of(context).push(
        MaterialPageRoute(builder: (_) => const ServerPickerScreen()),
      );
      return;
    }

    // "Find server": scan and adopt, then say plainly whether it worked.
    final state = context.read<AppState>();
    final found = await state.discoverServers();
    if (!mounted) return;
    if (found.isEmpty) {
      _toast('No server found on this Wi-Fi. Check the phone is on the same '
          'network as the computer running SecureChat.');
      return;
    }
    await state.adoptDiscoveredServer(found.first);
    if (!mounted) return;
    _toast('Using ${AppConfig.apiBaseUrl}');
  }

  void _toast(String message) {
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(SnackBar(content: Text(message)));
  }

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();

    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.symmetric(horizontal: 28, vertical: 24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const _Logo(),
                const SizedBox(height: 12),
                Text(
                  _registering ? 'Create your account' : 'Welcome back',
                  textAlign: TextAlign.center,
                  style: const TextStyle(
                    fontSize: 24,
                    fontWeight: FontWeight.w700,
                    color: AppColors.textPrimary,
                  ),
                ),
                const SizedBox(height: 6),
                Text(
                  _registering
                      ? 'Your number identifies your account. It can only be '
                          'registered once.'
                      : 'Sign in with the number and password you registered.',
                  textAlign: TextAlign.center,
                  style: const TextStyle(
                    fontSize: 13,
                    height: 1.4,
                    color: AppColors.textSecondary,
                  ),
                ),
                const SizedBox(height: 20),
                // The server is chosen first, because nothing works without it
                // and a wrong address is the most common reason a first-time
                // user cannot create an account.
                _ServerPanel(state: state),
                const SizedBox(height: 20),
                _buildForm(state),
                const SizedBox(height: 18),
                _modeSwitch(),
              ],
            ),
          ),
        ),
      ),
    );
  }

  /// Sign-up and sign-in as a segmented control.
  ///
  /// A text link at the bottom of a scrolling form is easy to miss, and a user
  /// with an existing account who cannot see "Sign in" reasonably concludes the
  /// app has no sign-in at all. Both options are now equally visible.
  Widget _modeSwitch() {
    return Container(
      padding: const EdgeInsets.all(4),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppColors.divider),
      ),
      child: Row(
        children: [
          _segment(
            label: 'Create account',
            selected: _registering,
            onTap: () => _setMode(true),
          ),
          _segment(
            label: 'Sign in',
            selected: !_registering,
            onTap: () => _setMode(false),
          ),
        ],
      ),
    );
  }

  Widget _segment({
    required String label,
    required bool selected,
    required VoidCallback onTap,
  }) {
    return Expanded(
      child: GestureDetector(
        onTap: onTap,
        behavior: HitTestBehavior.opaque,
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 160),
          padding: const EdgeInsets.symmetric(vertical: 11),
          decoration: BoxDecoration(
            color: selected ? AppColors.accent : Colors.transparent,
            borderRadius: BorderRadius.circular(9),
          ),
          child: Text(
            label,
            textAlign: TextAlign.center,
            style: TextStyle(
              fontSize: 14,
              fontWeight: FontWeight.w600,
              color: selected ? Colors.white : AppColors.textSecondary,
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildForm(AppState state) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (_registering) ...[
          TextField(
            controller: _nameController,
            textCapitalization: TextCapitalization.words,
            style: const TextStyle(fontSize: 15.5),
            decoration: const InputDecoration(
              hintText: 'Your name (optional)',
              prefixIcon: Icon(Icons.person_outline, size: 20),
            ),
          ),
          const SizedBox(height: 12),
        ],
        TextField(
          controller: _phoneController,
          focusNode: _phoneFocus,
          keyboardType: TextInputType.phone,
          autofocus: true,
          inputFormatters: [
            FilteringTextInputFormatter.allow(RegExp(r'[0-9+\-\s]')),
            LengthLimitingTextInputFormatter(18),
          ],
          style: const TextStyle(fontSize: 17),
          decoration: InputDecoration(
            hintText: '+91 98765 43210',
            labelText: 'Mobile number',
            prefixIcon: const Icon(Icons.phone_iphone, size: 20),
            suffixIcon: _checking
                ? const Padding(
                    padding: EdgeInsets.all(14),
                    child: SizedBox(
                      height: 16,
                      width: 16,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    ),
                  )
                : null,
          ),
          onChanged: (_) {
            if (_alreadyRegistered != null) {
              setState(() => _alreadyRegistered = null);
            }
          },
          onSubmitted: (_) => _checkNumber(),
          // Deliberately only one hook: setting both onSubmitted and
          // onEditingComplete makes Flutter call each of them, so a single press
          // of the keyboard's next button used to ask the server twice.
        ),
        if (_alreadyRegistered == true) ...[
          const SizedBox(height: 10),
          _Notice(
            text: 'This number already has an account. Use the sign-in form.',
            color: AppColors.warning,
            icon: Icons.info_outline,
          ),
        ],
        const SizedBox(height: 12),
        TextField(
          controller: _passwordController,
          obscureText: _obscure,
          style: const TextStyle(fontSize: 15.5),
          decoration: InputDecoration(
            labelText: 'Password',
            hintText: _registering ? 'At least 8 characters' : 'Your password',
            prefixIcon: const Icon(Icons.lock_outline, size: 20),
            suffixIcon: IconButton(
              icon: Icon(
                _obscure ? Icons.visibility_off : Icons.visibility,
                size: 20,
              ),
              onPressed: () => setState(() => _obscure = !_obscure),
            ),
          ),
          onSubmitted: (_) => _submit(),
        ),
        if (_registering) ...[
          const SizedBox(height: 10),
          const _Notice(
            text: 'Pick something you have not used elsewhere. A number can '
                'only be registered once, and there is no password reset.',
            color: AppColors.textSecondary,
            icon: Icons.shield_outlined,
          ),
        ],
        const SizedBox(height: 22),
        FilledButton(
          onPressed: state.busy ? null : _submit,
          child: state.busy
              ? const SizedBox(
                  height: 20,
                  width: 20,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : Text(_registering ? 'Create account' : 'Sign in'),
        ),
      ],
    );
  }
}

/// The server this install will talk to, with one-tap discovery.
///
/// Registration cannot succeed against the wrong address, so this sits above
/// the form rather than hidden in settings. A fresh install scans the Wi-Fi by
/// itself; if that finds nothing, the user can type an address or rescan.
class _ServerPanel extends StatefulWidget {
  const _ServerPanel({required this.state});

  final AppState state;

  @override
  State<_ServerPanel> createState() => _ServerPanelState();
}

class _ServerPanelState extends State<_ServerPanel> {
  bool _checking = false;
  bool _autoScanned = false;

  AppState get state => widget.state;

  @override
  void initState() {
    super.initState();
    // A fresh install points at the emulator alias, which no real phone can
    // reach. Rather than wait for a tap on a button the user has not read yet,
    // look for the LAN server once, as soon as the panel is on screen.
    if (AppConfig.apiBaseUrl == AppConfig.compiledDefaultUrl) {
      WidgetsBinding.instance.addPostFrameCallback((_) => _autoScan());
    }
  }

  Future<void> _autoScan() async {
    if (_autoScanned || !mounted) return;
    _autoScanned = true;
    setState(() => _checking = true);
    final found = await state.discoverServers();
    if (!mounted) return;
    if (found.isNotEmpty) await state.adoptDiscoveredServer(found.first);
    if (!mounted) return;
    setState(() => _checking = false);
  }

  /// Confirm the configured address answers, so the user is not told to type a
  /// password into a form that is about to fail on a network error.
  Future<void> _verify() async {
    setState(() => _checking = true);
    await state.testServer();
    if (!mounted) return;
    setState(() => _checking = false);
  }

  /// Scan the local network and adopt the first server that answers.
  Future<void> _scan() async {
    setState(() => _checking = true);
    final found = await state.discoverServers();
    if (!mounted) return;
    if (found.isNotEmpty) {
      await state.adoptDiscoveredServer(found.first);
    }
    if (!mounted) return;
    setState(() => _checking = false);
    await _verify();
  }

  void _openPicker() {
    Navigator.of(context).push(
      MaterialPageRoute(builder: (_) => const ServerPickerScreen()),
    );
  }

  @override
  Widget build(BuildContext context) {
    final cleartext = AppConfig.usesCleartext;
    // The compiled default is the emulator alias, which cannot work on a real
    // phone. Saying so is more useful than letting the user submit and fail.
    final unset = AppConfig.apiBaseUrl == AppConfig.compiledDefaultUrl;

    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(
          color: unset
              ? AppColors.warning.withValues(alpha: 0.5)
              : AppColors.divider,
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(
                unset ? Icons.cloud_off_outlined : Icons.dns_outlined,
                size: 17,
                color: unset ? AppColors.warning : AppColors.textSecondary,
              ),
              const SizedBox(width: 9),
              Expanded(
                child: Text(
                  AppConfig.apiBaseUrl,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(
                    fontSize: 13,
                    fontFamily: 'monospace',
                    color: AppColors.textPrimary,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 9),
          if (unset)
            const Text(
              'No server set yet. On this Wi-Fi the app finds it automatically — '
              'otherwise enter the address your server printed on screen.',
              style: TextStyle(
                fontSize: 12,
                height: 1.4,
                color: AppColors.textSecondary,
              ),
            )
          else if (cleartext)
            const Text(
              'Messages are end-to-end encrypted regardless. This address is '
              'not encrypted in transit, so metadata such as who is talking to '
              'whom is visible to the network.',
              style: TextStyle(
                fontSize: 12,
                height: 1.4,
                color: AppColors.warning,
              ),
            ),
          const SizedBox(height: 10),
          Row(
            children: [
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: _checking ? null : _scan,
                  icon: _checking
                      ? const SizedBox(
                          height: 14,
                          width: 14,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Icon(Icons.wifi_find_outlined, size: 17),
                  label: const Text('Find server'),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: _checking ? null : _openPicker,
                  icon: const Icon(Icons.edit_outlined, size: 16),
                  label: const Text('Enter address'),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

/// A short inline note, used for guidance and warnings.
class _Notice extends StatelessWidget {
  const _Notice({required this.text, required this.color, required this.icon});

  final String text;
  final Color color;
  final IconData icon;

  @override
  Widget build(BuildContext context) {
    return Row(
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
    );
  }
}

/// The app mark: a padlock inside a speech bubble.
class _Logo extends StatelessWidget {
  const _Logo();

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Container(
        width: 88,
        height: 88,
        decoration: BoxDecoration(
          color: AppColors.accent,
          borderRadius: BorderRadius.circular(26),
        ),
        child: const Stack(
          alignment: Alignment.center,
          children: [
            Icon(Icons.chat_bubble, size: 48, color: Colors.white),
            Icon(Icons.lock, size: 20, color: AppColors.accent),
          ],
        ),
      ),
    );
  }
}
