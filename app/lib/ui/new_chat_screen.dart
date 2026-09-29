import 'dart:async';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../net/api.dart';
import '../state/app_state.dart';
import '../state/chat_store.dart';
import 'chat_screen.dart';
import 'theme.dart';

/// Find a contact by phone number and start a 1:1 chat.
class NewChatScreen extends StatefulWidget {
  const NewChatScreen({super.key});

  @override
  State<NewChatScreen> createState() => _NewChatScreenState();
}

class _NewChatScreenState extends State<NewChatScreen> {
  final _controller = TextEditingController();
  Timer? _debounce;

  List<Map<String, dynamic>> _results = [];
  bool _searching = false;
  String? _error;

  @override
  void dispose() {
    _debounce?.cancel();
    _controller.dispose();
    super.dispose();
  }

  /// Debounced so typing a phone number does not fire a request per digit.
  void _onChanged(String value) {
    _debounce?.cancel();
    final digits = value.replaceAll(RegExp(r'[^\d+]'), '');
    if (digits.length < 3) {
      setState(() {
        _results = [];
        _error = null;
      });
      return;
    }
    _debounce = Timer(const Duration(milliseconds: 350), () => _search(value));
  }

  Future<void> _search(String query) async {
    final state = context.read<AppState>();
    setState(() {
      _searching = true;
      _error = null;
    });
    try {
      final found = await state.api.searchUsers(query);
      if (!mounted) return;
      setState(() {
        _results = found;
        _searching = false;
      });
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() {
        _error = e.message ?? e.code;
        _searching = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = '$e';
        _searching = false;
      });
    }
  }

  Future<void> _open(Map<String, dynamic> user) async {
    final state = context.read<AppState>();
    final id = '${user['id']}';
    final title = '${user['displayName'] ?? 'Unknown'}';
    final colorIndex = (user['avatarColor'] as num?)?.toInt() ?? 0;

    // The deterministic chat id: both participants sort to the same value, so
    // each side addresses the same thread without negotiating an id.
    final ids = [state.userId ?? '', id]..sort();
    final chatId = '${ids[0]}|${ids[1]}';

    state.chats.setSummary(
      ChatSummary(
        chatId: chatId,
        type: 'direct',
        title: title,
        peerId: id,
        avatarColor: colorIndex,
      ),
    );

    if (!mounted) return;
    await Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => ChatScreen(
          chatId: chatId,
          title: title,
          peerId: id,
          avatarColor: colorIndex,
        ),
      ),
    );
    if (mounted) setState(() {});
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('New chat')),
      body: Column(
        children: [
          Container(
            color: AppColors.appBar,
            padding: const EdgeInsets.fromLTRB(12, 4, 12, 10),
            child: TextField(
              controller: _controller,
              autofocus: true,
              keyboardType: TextInputType.phone,
              style: const TextStyle(fontSize: 15),
              onChanged: _onChanged,
              decoration: const InputDecoration(
                hintText: 'Enter a phone number',
                prefixIcon: Icon(Icons.search, size: 20),
                isDense: true,
              ),
            ),
          ),
          Expanded(child: _buildBody()),
        ],
      ),
    );
  }

  Widget _buildBody() {
    if (_searching) {
      return const Center(child: CircularProgressIndicator());
    }
    if (_error != null) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(28),
          child: Text(
            _error!,
            textAlign: TextAlign.center,
            style: const TextStyle(color: AppColors.textSecondary),
          ),
        ),
      );
    }
    if (_results.isEmpty) {
      return const Center(
        child: Padding(
          padding: EdgeInsets.all(32),
          child: Text(
            'Search by phone number to start a chat.\n\nThe other person must '
            'already have SecureChat installed and shared their number.',
            textAlign: TextAlign.center,
            style: TextStyle(
              fontSize: 13.5,
              height: 1.5,
              color: AppColors.textSecondary,
            ),
          ),
        ),
      );
    }

    return ListView.separated(
      itemCount: _results.length,
      separatorBuilder: (_, __) => const Divider(height: 0.5, indent: 76),
      itemBuilder: (_, i) {
        final user = _results[i];
        final hasKeys = user['hasKeys'] == true;
        return ListTile(
          contentPadding:
              const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
          leading: ContactAvatar(
            name: '${user['displayName'] ?? '?'}',
            colorIndex: (user['avatarColor'] as num?)?.toInt() ?? 0,
            radius: 23,
          ),
          title: Text(
            '${user['displayName'] ?? 'Unknown'}',
            style: const TextStyle(
              fontSize: 15.5,
              fontWeight: FontWeight.w500,
            ),
          ),
          subtitle: Text(
            '${user['phone'] ?? ''}',
            style: const TextStyle(
              fontSize: 12.5,
              color: AppColors.textSecondary,
            ),
          ),
          trailing: hasKeys
              ? const Icon(Icons.lock, size: 15, color: AppColors.accent)
              : const StatusPill(
                  label: 'no keys',
                  color: AppColors.warning,
                ),
          onTap: () => _open(user),
        );
      },
    );
  }
}
