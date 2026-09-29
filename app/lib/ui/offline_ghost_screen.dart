import 'dart:async';

import 'package:flutter/material.dart';
import 'package:permission_handler/permission_handler.dart';

import '../services/offline_ghost_service.dart';
import 'theme.dart';

/// Offline mesh chat for when there is no server to talk to.
///
/// ## This screen is not encrypted
///
/// Every message here travels as plain text over the radio, in range of anyone,
/// and is relayed onward by intermediate devices. A permanent banner states
/// this, the composer repeats it in the hint text, and each bubble says
/// "readable by relays" in place of a padlock. Nobody should walk away believing
/// this channel is protected.
class OfflineGhostScreen extends StatefulWidget {
  const OfflineGhostScreen({super.key});

  @override
  State<OfflineGhostScreen> createState() => _OfflineGhostScreenState();
}

class _OfflineGhostScreenState extends State<OfflineGhostScreen> {
  final OfflineGhostService _ghost = OfflineGhostService();
  final TextEditingController _controller = TextEditingController();
  final ScrollController _scroll = ScrollController();

  /// "ALL", or the name of one selected peer.
  String _target = 'ALL';

  /// Permission state, so the UI can explain itself rather than silently
  /// showing an empty peer list.
  bool _permissionsGranted = false;

  @override
  void initState() {
    super.initState();
    _ghost.addListener(_onGhostChanged);
    unawaited(_bootstrap());
  }

  @override
  void dispose() {
    _ghost.removeListener(_onGhostChanged);
    _ghost.dispose();
    _controller.dispose();
    _scroll.dispose();
    super.dispose();
  }

  Future<void> _bootstrap() async {
    final granted = await _requestPermissions();
    if (!mounted) return;
    setState(() => _permissionsGranted = granted);
    if (granted) await _ghost.start();
  }

  /// Android 12+ splits Bluetooth into scan/advertise/connect, each needing a
  /// runtime grant. The plugin fails without them.
  Future<bool> _requestPermissions() async {
    final result = await [
      Permission.bluetoothScan,
      Permission.bluetoothAdvertise,
      Permission.bluetoothConnect,
      Permission.nearbyWifiDevices,
      Permission.locationWhenInUse,
    ].request();
    return result.values.every((s) => s.isGranted || s.isLimited);
  }

  /// Route peer-list and message changes into a rebuild.
  ///
  /// The service is a [ChangeNotifier] precisely so the screen need not keep a
  /// parallel copy of the list and drift out of sync with it.
  void _onGhostChanged() {
    if (!mounted) return;
    setState(() {});
    // Stick to the bottom as traffic arrives.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!_scroll.hasClients) return;
      _scroll.animateTo(
        _scroll.position.maxScrollExtent,
        duration: const Duration(milliseconds: 180),
        curve: Curves.easeOut,
      );
    });
  }

  void _send() {
    final text = _controller.text;
    if (text.trim().isEmpty) return;
    if (_target == 'ALL') {
      _ghost.sendBroadcast(text);
    } else {
      _ghost.sendWhisper(_target, text);
    }
    _controller.clear();
  }

  @override
  Widget build(BuildContext context) {
    final peers = _ghost.nearbyDevices;
    final messages = _ghost.messages;
    final direct = _target != 'ALL';

    return Scaffold(
      appBar: AppBar(
        title: Text(
          _ghost.myName,
          style: const TextStyle(
            fontFamily: 'monospace',
            fontSize: 15,
            color: AppColors.accent,
          ),
        ),
        actions: [
          Center(
            child: Padding(
              padding: const EdgeInsets.only(right: 14),
              child: Text(
                '${peers.length} nearby',
                style: const TextStyle(
                  fontSize: 12.5,
                  color: AppColors.textSecondary,
                ),
              ),
            ),
          ),
          IconButton(
            tooltip: 'Clear transcript',
            onPressed: messages.isEmpty ? null : _ghost.clearHistory,
            icon: const Icon(Icons.delete_sweep_outlined, size: 20),
          ),
        ],
      ),
      body: Column(
        children: [
          const _NotEncryptedBanner(),
          if (!_permissionsGranted) const _PermissionBanner(),
          if (_ghost.lastError != null)
            _ErrorBanner(message: _ghost.lastError!),
          _PeerStrip(
            peers: peers,
            target: _target,
            onSelect: (name) => setState(() => _target = name),
          ),
          Expanded(
            child: messages.isEmpty
                ? const _EmptyState()
                : ListView.builder(
                    controller: _scroll,
                    padding: const EdgeInsets.fromLTRB(12, 10, 12, 10),
                    itemCount: messages.length,
                    itemBuilder: (context, i) => _Bubble(message: messages[i]),
                  ),
          ),
          _Composer(
            controller: _controller,
            target: _target,
            direct: direct,
            enabled: _permissionsGranted && _ghost.isRunning,
            onSend: _send,
          ),
        ],
      ),
    );
  }
}

/// Permanent, unmissable statement that this channel has no cipher.
///
/// The alternative - styling it like the encrypted chat and hoping nobody
/// notices the missing padlock - is how people get hurt by a real product.
class _NotEncryptedBanner extends StatelessWidget {
  const _NotEncryptedBanner();

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      color: AppColors.danger.withValues(alpha: 0.16),
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 9),
      child: const Row(
        children: [
          Icon(
            Icons.no_encryption_gmailerrorred,
            size: 17,
            color: AppColors.danger,
          ),
          SizedBox(width: 10),
          Expanded(
            child: Text(
              'NOT encrypted. Anyone in radio range can read these messages, '
              'and relays carry them on. Use this only when you have no signal.',
              style: TextStyle(
                fontSize: 11.5,
                height: 1.35,
                color: AppColors.danger,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

/// Shown when Bluetooth permission was refused, with a way to fix it.
class _PermissionBanner extends StatelessWidget {
  const _PermissionBanner();

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      color: AppColors.warning.withValues(alpha: 0.14),
      padding: const EdgeInsets.fromLTRB(14, 10, 8, 10),
      child: Row(
        children: [
          const Icon(
            Icons.bluetooth_disabled,
            size: 17,
            color: AppColors.warning,
          ),
          const SizedBox(width: 10),
          const Expanded(
            child: Text(
              'Bluetooth permission is needed to find nearby devices.',
              style: TextStyle(fontSize: 12, color: AppColors.warning),
            ),
          ),
          TextButton(onPressed: openAppSettings, child: const Text('Settings')),
        ],
      ),
    );
  }
}

class _ErrorBanner extends StatelessWidget {
  const _ErrorBanner({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      color: AppColors.danger.withValues(alpha: 0.12),
      padding: const EdgeInsets.all(12),
      child: Text(
        message,
        style: const TextStyle(fontSize: 12, color: AppColors.danger),
      ),
    );
  }
}

/// Horizontal list of peers, with "ALL" pinned first as the broadcast target.
class _PeerStrip extends StatelessWidget {
  const _PeerStrip({
    required this.peers,
    required this.target,
    required this.onSelect,
  });

  final List<GhostDevice> peers;
  final String target;
  final ValueChanged<String> onSelect;

  @override
  Widget build(BuildContext context) {
    return Container(
      height: 86,
      color: AppColors.surface,
      child: peers.isEmpty
          ? const Center(
              child: Text(
                'Scanning for nearby devices...',
                style: TextStyle(
                  fontSize: 12.5,
                  color: AppColors.textSecondary,
                ),
              ),
            )
          : ListView.builder(
              scrollDirection: Axis.horizontal,
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
              itemCount: peers.length + 1,
              itemBuilder: (context, index) {
                if (index == 0) {
                  return _PeerChip(
                    label: 'ALL',
                    caption: '${peers.length} devices',
                    icon: Icons.campaign_outlined,
                    selected: target == 'ALL',
                    onTap: () => onSelect('ALL'),
                  );
                }
                final device = peers[index - 1];
                return _PeerChip(
                  label: device.name,
                  caption: 'direct',
                  icon: Icons.person_outline,
                  selected: target == device.name,
                  onTap: () => onSelect(device.name),
                );
              },
            ),
    );
  }
}

class _PeerChip extends StatelessWidget {
  const _PeerChip({
    required this.label,
    required this.caption,
    required this.icon,
    required this.selected,
    required this.onTap,
  });

  final String label;
  final String caption;
  final IconData icon;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final accent = selected ? AppColors.accent : AppColors.textSecondary;
    return GestureDetector(
      onTap: onTap,
      child: Container(
        width: 96,
        margin: const EdgeInsets.only(right: 8),
        padding: const EdgeInsets.all(8),
        decoration: BoxDecoration(
          color: selected
              ? AppColors.accent.withValues(alpha: 0.14)
              : AppColors.elevated,
          border: Border.all(
            color: selected ? AppColors.accent : AppColors.divider,
            width: selected ? 2 : 1,
          ),
          borderRadius: BorderRadius.circular(12),
        ),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(icon, size: 19, color: accent),
            const SizedBox(height: 5),
            Text(
              label,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              textAlign: TextAlign.center,
              style: TextStyle(
                fontSize: 11,
                fontWeight: FontWeight.w600,
                color: selected
                    ? AppColors.textPrimary
                    : AppColors.textSecondary,
              ),
            ),
            const SizedBox(height: 2),
            Text(
              caption,
              style: const TextStyle(
                fontSize: 9,
                color: AppColors.textSecondary,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _Bubble extends StatelessWidget {
  const _Bubble({required this.message});

  final GhostMessage message;

  @override
  Widget build(BuildContext context) {
    final mine = message.isMine;
    final direct = message.type == 'private';

    return Align(
      alignment: mine ? Alignment.centerRight : Alignment.centerLeft,
      child: Container(
        margin: const EdgeInsets.symmetric(vertical: 4),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 9),
        constraints: BoxConstraints(
          maxWidth: MediaQuery.of(context).size.width * 0.78,
        ),
        decoration: BoxDecoration(
          color: mine
              ? AppColors.accentDark
              : direct
                  ? AppColors.elevated
                  : AppColors.surface,
          borderRadius: BorderRadius.circular(12),
          border: direct && !mine
              ? Border.all(
                  color: AppColors.linkBlue.withValues(alpha: 0.35),
                )
              : null,
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              direct ? '${message.from} to ${message.to}' : message.from,
              style: TextStyle(
                fontSize: 10,
                fontFamily: 'monospace',
                color: direct ? AppColors.linkBlue : AppColors.textSecondary,
              ),
            ),
            const SizedBox(height: 3),
            Text(
              message.text,
              style: const TextStyle(fontSize: 14.5, height: 1.35),
            ),
            const SizedBox(height: 3),
            Text(
              // No padlock glyph here: there is no encryption to represent.
              '${_clock(message.time)} - readable by relays',
              style: const TextStyle(
                fontSize: 9.5,
                color: AppColors.textSecondary,
              ),
            ),
          ],
        ),
      ),
    );
  }

  static String _clock(DateTime time) =>
      '${time.hour.toString().padLeft(2, '0')}:'
      '${time.minute.toString().padLeft(2, '0')}';
}

class _EmptyState extends StatelessWidget {
  const _EmptyState();

  @override
  Widget build(BuildContext context) {
    return const Center(
      child: Padding(
        padding: EdgeInsets.all(28),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.cell_tower, size: 40, color: AppColors.textSecondary),
            SizedBox(height: 14),
            Text(
              'No mesh traffic yet',
              style: TextStyle(
                fontSize: 15,
                fontWeight: FontWeight.w600,
                color: AppColors.textPrimary,
              ),
            ),
            SizedBox(height: 7),
            Text(
              'Messages travel directly between phones in range, with no server '
              'involved. Tap ALL to broadcast, or pick a device to send to one.',
              textAlign: TextAlign.center,
              style: TextStyle(
                fontSize: 12.5,
                height: 1.45,
                color: AppColors.textSecondary,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _Composer extends StatelessWidget {
  const _Composer({
    required this.controller,
    required this.target,
    required this.direct,
    required this.enabled,
    required this.onSend,
  });

  final TextEditingController controller;
  final String target;
  final bool direct;
  final bool enabled;
  final VoidCallback onSend;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.fromLTRB(10, 9, 10, 10),
      decoration: const BoxDecoration(
        color: AppColors.surface,
        border: Border(top: BorderSide(color: AppColors.divider)),
      ),
      child: SafeArea(
        top: false,
        child: Row(
          children: [
            Expanded(
              child: TextField(
                controller: controller,
                enabled: enabled,
                minLines: 1,
                maxLines: 4,
                textInputAction: TextInputAction.send,
                onSubmitted: (_) => onSend(),
                style: const TextStyle(fontSize: 15),
                decoration: InputDecoration(
                  hintText: direct
                      ? 'Direct to $target (unencrypted)'
                      : 'Broadcast to everyone (unencrypted)',
                  isDense: true,
                  filled: true,
                  fillColor: AppColors.elevated,
                  contentPadding: const EdgeInsets.symmetric(
                    horizontal: 14,
                    vertical: 12,
                  ),
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(22),
                    borderSide: BorderSide.none,
                  ),
                ),
              ),
            ),
            const SizedBox(width: 8),
            IconButton.filled(
              onPressed: enabled ? onSend : null,
              style: IconButton.styleFrom(
                backgroundColor:
                    direct ? AppColors.linkBlue : AppColors.accent,
              ),
              icon: Icon(
                direct ? Icons.send_rounded : Icons.campaign_rounded,
                size: 20,
                color: Colors.black,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
