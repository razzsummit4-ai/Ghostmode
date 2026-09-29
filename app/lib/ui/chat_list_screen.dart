import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';

import '../state/app_state.dart';
import '../state/chat_store.dart';
import '../net/api.dart';
import 'chat_screen.dart';
import 'new_chat_screen.dart';
import 'offline_ghost_screen.dart';
import 'settings_screen.dart';
import 'theme.dart';

/// The conversation list.
///
/// The server returns ciphertext for every preview, so each row is decrypted on
/// this device before it is drawn.
class ChatListScreen extends StatefulWidget {
  const ChatListScreen({super.key});

  @override
  State<ChatListScreen> createState() => _ChatListScreenState();
}

class _ChatListScreenState extends State<ChatListScreen> {
  final _searchController = TextEditingController();
  bool _loading = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _refresh());
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  Future<void> _refresh() async {
    final state = context.read<AppState>();
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final chats = await state.api.chats();
      for (final c in chats) {
        state.chats.setSummary(
          ChatSummary(
            chatId: '${c['chatId']}',
            type: '${c['type'] ?? 'direct'}',
            title: '${c['title'] ?? 'Unknown'}',
            peerId: c['peerId'] as String?,
            groupId: c['groupId'] as String?,
            avatarColor: (c['avatarColor'] as num?)?.toInt() ?? 0,
            disappearingMessagesSeconds:
                (c['disappearingMessagesSeconds'] as num?)?.toInt() ?? 0,
          ),
        );
      }
      // Load previews. Each is decrypted locally; failures degrade to a
      // placeholder rather than hiding the conversation.
      for (final summary in state.chats.summaries) {
        final preview = (chats.firstWhere(
          (c) => '${c['chatId']}' == summary.chatId,
          orElse: () => const {},
        ))['lastMessage'];
        if (preview is Map && preview.isNotEmpty) {
          final row = await state.messaging.loadPreview(
            summary,
            Map<String, dynamic>.from(preview),
          );
          if (row != null) summary.lastMessage = row;
        }
      }
    } on ApiException catch (e) {
      // A rejected token is not a list-rendering problem: the session is gone.
      // Hand it to the app, which returns the user to sign-in and keeps their
      // device keys, instead of showing a dead "Missing bearer token" error.
      if (e.status == 401) {
        await state.handleUnauthorized();
        return;
      }
      if (mounted) setState(() => _error = e.message ?? e.code);
    } catch (e) {
      if (mounted) setState(() => _error = '$e');
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final summaries = state.chats.summaries;

    return Scaffold(
      appBar: AppBar(
        title: const Text('SecureChat'),
        actions: [
          // Offline mesh. Kept behind an explicit icon rather than mixed into
          // the conversation list, because this channel is NOT encrypted and must
          // never be mistaken for the chats above it.
          IconButton(
            tooltip: 'Offline mesh - NOT encrypted',
            icon: const Icon(Icons.cell_tower),
            onPressed: () => Navigator.of(context).push(
              MaterialPageRoute(builder: (_) => const OfflineGhostScreen()),
            ),
          ),
          IconButton(
            tooltip: 'New chat',
            icon: const Icon(Icons.edit_square),
            onPressed: () => Navigator.of(context).push(
              MaterialPageRoute(builder: (_) => const NewChatScreen()),
            ),
          ),
          IconButton(
            tooltip: 'Settings',
            icon: const Icon(Icons.settings_outlined),
            onPressed: () => Navigator.of(context).push(
              MaterialPageRoute(builder: (_) => const SettingsScreen()),
            ),
          ),
        ],
      ),
      body: Column(
        children: [
          Container(
            color: AppColors.appBar,
            padding: const EdgeInsets.fromLTRB(12, 4, 12, 10),
            child: TextField(
              controller: _searchController,
              style: const TextStyle(fontSize: 15),
              decoration: const InputDecoration(
                hintText: 'Search conversations',
                prefixIcon: Icon(Icons.search, size: 20),
                isDense: true,
              ),
              onChanged: (_) => setState(() {}),
            ),
          ),
          Expanded(child: _buildBody(state, summaries)),
        ],
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: () => Navigator.of(context).push(
          MaterialPageRoute(builder: (_) => const NewChatScreen()),
        ),
        child: const Icon(Icons.chat),
      ),
    );
  }

  Widget _buildBody(AppState state, List<ChatSummary> all) {
    if (_loading) {
      return const Center(child: CircularProgressIndicator());
    }
    if (_error != null) {
      return _ErrorView(message: _error!, onRetry: _refresh);
    }

    final query = _searchController.text.trim().toLowerCase();
    final visible = query.isEmpty
        ? all
        : all.where((s) => s.title.toLowerCase().contains(query)).toList();

    if (visible.isEmpty) {
      return _EmptyView(hasQuery: query.isNotEmpty);
    }

    return RefreshIndicator(
      onRefresh: _refresh,
      color: AppColors.accent,
      backgroundColor: AppColors.elevated,
      child: ListView.separated(
        itemCount: visible.length,
        separatorBuilder: (_, __) =>
            const Divider(height: 0.5, indent: 78, endIndent: 12),
        itemBuilder: (_, i) => _ChatTile(summary: visible[i]),
      ),
    );
  }
}

/// One conversation row.
class _ChatTile extends StatelessWidget {
  const _ChatTile({required this.summary});

  final ChatSummary summary;

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final last = summary.lastMessage;
    final identityChanged =
        summary.peerId != null &&
            state.sessions.identityChanges.contains(summary.peerId);

    return ListTile(
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
      leading: Stack(
        clipBehavior: Clip.none,
        children: [
          ContactAvatar(
            name: summary.isGroup ? '# ${summary.title}' : summary.title,
            colorIndex: summary.avatarColor,
            radius: 25,
          ),
          if (summary.unreadCount > 0)
            Positioned(
              right: -6,
              top: -4,
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
                decoration: BoxDecoration(
                  color: AppColors.accent,
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Text(
                  summary.unreadCount > 99 ? '99+' : '${summary.unreadCount}',
                  style: const TextStyle(
                    fontSize: 11,
                    fontWeight: FontWeight.w700,
                    color: Colors.white,
                  ),
                ),
              ),
            ),
        ],
      ),
      title: Row(
        children: [
          Expanded(
            child: Text(
              summary.title,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(
                fontSize: 16,
                fontWeight: FontWeight.w600,
                color: AppColors.textPrimary,
              ),
            ),
          ),
          if (last != null)
            Text(
              _formatTime(last.createdAt),
              style: const TextStyle(
                fontSize: 11.5,
                color: AppColors.textSecondary,
              ),
            ),
        ],
      ),
      subtitle: Padding(
        padding: const EdgeInsets.only(top: 3),
        child: Row(
          children: [
            if (last?.isMine == true) ...[
              const Icon(Icons.done_all, size: 14, color: AppColors.linkBlue),
              const SizedBox(width: 4),
            ],
            Expanded(
              child: Text(
                _preview(last),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  fontSize: 13.5,
                  color: last?.kind == 'undecryptable'
                      ? AppColors.danger
                      : AppColors.textSecondary,
                ),
              ),
            ),
            if (identityChanged)
              const Padding(
                padding: EdgeInsets.only(left: 6),
                child:
                    Icon(Icons.gpp_maybe, size: 15, color: AppColors.warning),
              ),
          ],
        ),
      ),
      onTap: () async {
        await Navigator.of(context).push(
          MaterialPageRoute(
            builder: (_) => ChatScreen(
              chatId: summary.chatId,
              title: summary.title,
              peerId: summary.peerId,
              groupId: summary.groupId,
              isGroup: summary.isGroup,
              avatarColor: summary.avatarColor,
            ),
          ),
        );
      },
    );
  }

  String _preview(ChatRow? row) {
    if (row == null) return 'No messages yet';
    if (row.kind == 'expired') return 'Message expired';
    return row.text;
  }

  static String _formatTime(DateTime when) {
    final now = DateTime.now();
    final sameDay = when.year == now.year &&
        when.month == now.month &&
        when.day == now.day;
    if (sameDay) return DateFormat.jm().format(when);
    if (now.difference(when).inDays < 7) return DateFormat.E().format(when);
    return DateFormat.Md().format(when);
  }
}

class _EmptyView extends StatelessWidget {
  const _EmptyView({required this.hasQuery});

  final bool hasQuery;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              hasQuery ? Icons.search_off : Icons.forum_outlined,
              size: 52,
              color: AppColors.textSecondary,
            ),
            const SizedBox(height: 14),
            Text(
              hasQuery ? 'No matching conversations' : 'No conversations yet',
              style: const TextStyle(
                fontSize: 16,
                fontWeight: FontWeight.w600,
                color: AppColors.textPrimary,
              ),
            ),
            const SizedBox(height: 6),
            Text(
              hasQuery
                  ? 'Try a different search.'
                  : 'Start a chat. Messages are encrypted on this device '
                      'before they are sent.',
              textAlign: TextAlign.center,
              style: const TextStyle(
                fontSize: 13.5,
                height: 1.4,
                color: AppColors.textSecondary,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _ErrorView extends StatelessWidget {
  const _ErrorView({required this.message, required this.onRetry});

  final String message;
  final Future<void> Function() onRetry;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.cloud_off, size: 48, color: AppColors.danger),
            const SizedBox(height: 14),
            const Text(
              'Could not load your chats',
              style: TextStyle(
                fontSize: 16,
                fontWeight: FontWeight.w600,
                color: AppColors.textPrimary,
              ),
            ),
            const SizedBox(height: 6),
            Text(
              message,
              textAlign: TextAlign.center,
              style: const TextStyle(
                fontSize: 13,
                color: AppColors.textSecondary,
              ),
            ),
            const SizedBox(height: 20),
            OutlinedButton(
              onPressed: onRetry,
              child: const Text('Try again'),
            ),
          ],
        ),
      ),
    );
  }
}
