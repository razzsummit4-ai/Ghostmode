import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../net/api.dart';
import '../state/app_state.dart';
import '../state/chat_store.dart';
import 'attachment_sheet.dart';
import 'message_bubble.dart';
import 'chat_info_screen.dart';
import 'safety_number_screen.dart';
import 'theme.dart';

/// A single conversation.
///
/// The composer encrypts on submit; the list decrypts what arrives. No plaintext
/// leaves this widget, and none is retained after the bubble is drawn.
class ChatScreen extends StatefulWidget {
  const ChatScreen({
    super.key,
    required this.chatId,
    required this.title,
    this.peerId,
    this.groupId,
    this.isGroup = false,
    this.avatarColor = 0,
  });

  final String chatId;
  final String title;
  final String? peerId;
  final String? groupId;
  final bool isGroup;
  final int avatarColor;

  @override
  State<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> {
  final _composerController = TextEditingController();
  final _scrollController = ScrollController();
  final _composerFocus = FocusNode();

  bool _loading = true;
  String? _error;

  /// Self-addressed encryption key id, unused for 1:1 but kept per chat so a
  /// group conversation can rotate its own chain without touching the others.
  int _disappearingSeconds = 0;

  StreamSubscription<Map<String, dynamic>>? _incoming;
  Timer? _typingDebounce;
  bool _sentTypingRecently = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _load());
    // Subscribe to the live feed so messages appear without a manual refresh.
    final state = context.read<AppState>();
    _incoming = state.realtime.messages.listen(_onIncoming);
  }

  @override
  void dispose() {
    _incoming?.cancel();
    _typingDebounce?.cancel();
    _composerController.dispose();
    _scrollController.dispose();
    _composerFocus.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    final state = context.read<AppState>();
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      await state.messaging.loadThread(widget.chatId);
      _disappearingSeconds =
          state.chats.summary(widget.chatId)?.disappearingMessagesSeconds ?? 0;
    } on ApiException catch (e) {
      if (mounted) setState(() => _error = e.message ?? e.code);
    } catch (e) {
      if (mounted) setState(() => _error = '$e');
    } finally {
      if (mounted) {
        setState(() => _loading = false);
        _scrollToBottom();
      }
    }
  }

  /// A message arrived on the live socket.
  ///
  /// [AppState] already decrypted it and stored the row, so this only has to
  /// decide whether the open screen should react.
  void _onIncoming(Map<String, dynamic> wire) {
    final chatId = '${wire['chatId']}';
    if (chatId != widget.chatId || !mounted) return;
    setState(() {});
    _scrollToBottom();
    // Seeing the message is a read receipt.
    unawaited(_markRead());
  }

  Future<void> _markRead() async {
    final state = context.read<AppState>();
    final pending = state.chats.pendingRead(widget.chatId);
    if (pending.isEmpty) return;
    state.chats.markReadLocally(widget.chatId);
    try {
      await state.api.markStatus(pending, 'read');
    } catch (_) {
      // A failed receipt is retried the next time the thread is opened.
    }
  }

  void _scrollToBottom() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!_scrollController.hasClients) return;
      _scrollController.animateTo(
        _scrollController.position.maxScrollExtent,
        duration: const Duration(milliseconds: 220),
        curve: Curves.easeOut,
      );
    });
  }

  void _onComposerChanged(String value) {
    final state = context.read<AppState>();
    final peer = widget.peerId;
    if (peer == null) return;

    // Throttle: one "typing" event per burst, never per keystroke.
    if (value.trim().isNotEmpty) {
      if (!_sentTypingRecently) {
        _sentTypingRecently = true;
        state.realtime.sendTyping(receiverId: peer, typing: true);
      }
      _typingDebounce?.cancel();
      _typingDebounce = Timer(const Duration(seconds: 3), () {
        _sentTypingRecently = false;
        state.realtime.sendTyping(receiverId: peer, typing: false);
      });
    }
    if (state.chats.isPeerTyping(peer)) setState(() {});
  }

  Future<void> _send() async {
    final text = _composerController.text.trim();
    if (text.isEmpty) return;
    final state = context.read<AppState>();
    final peer = widget.peerId;
    if (peer == null) return;

    _composerController.clear();
    _typingDebounce?.cancel();
    _sentTypingRecently = false;
    state.realtime.sendTyping(receiverId: peer, typing: false);

    setState(() {});
    _scrollToBottom();

    await state.messaging.sendText(
      chatId: widget.chatId,
      peerId: peer,
      groupId: widget.groupId,
      text: text,
      expiresInSeconds: _disappearingSeconds,
    );
    if (mounted) _scrollToBottom();
  }

  Future<void> _sendAttachment(Uint8List bytes, String name, String mime,
      String kind) async {
    final state = context.read<AppState>();
    final peer = widget.peerId;
    if (peer == null) return;

    setState(() => _loading = true);
    try {
      await state.messaging.sendMedia(
        chatId: widget.chatId,
        peerId: peer,
        groupId: widget.groupId,
        bytes: bytes,
        fileName: name,
        mime: mime,
        kind: kind,
        expiresInSeconds: _disappearingSeconds,
      );
    } catch (e) {
      if (mounted) _toast('Attachment failed to send.');
    } finally {
      if (mounted) {
        setState(() => _loading = false);
        _scrollToBottom();
      }
    }
  }

  void _toast(String message) {
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(SnackBar(content: Text(message)));
  }

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final rows = state.chats.thread(widget.chatId);
    final peerTyping =
        widget.peerId != null && state.chats.isPeerTyping(widget.peerId!);

    return Scaffold(
      appBar: AppBar(
        titleSpacing: 0,
        title: Row(
          children: [
            ContactAvatar(
              name: widget.isGroup ? '# ${widget.title}' : widget.title,
              colorIndex: widget.avatarColor,
              radius: 17,
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(
                    widget.title,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(fontSize: 16),
                  ),
                  Text(
                    peerTyping ? 'typing…' : 'tap to view contact info',
                    style: TextStyle(
                      fontSize: 11.5,
                      color: peerTyping
                          ? AppColors.accent
                          : AppColors.textSecondary,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
        actions: [
          if (!widget.isGroup)
            IconButton(
              tooltip: 'Verify safety number',
              icon: const Icon(Icons.shield_outlined),
              onPressed: _openSafetyNumber,
            ),
          IconButton(
            tooltip: 'Chat info',
            icon: const Icon(Icons.info_outline),
            onPressed: () => Navigator.of(context).push(
              MaterialPageRoute(
                builder: (_) => ChatInfoScreen(
                  chatId: widget.chatId,
                  title: widget.title,
                  peerId: widget.peerId,
                  groupId: widget.groupId,
                  isGroup: widget.isGroup,
                ),
              ),
            ),
          ),
        ],
      ),
      body: Column(
        children: [
          EncryptionBanner(
            onTap: widget.isGroup ? _showGroupInfo : _openSafetyNumber,
            subtitle: widget.isGroup
                ? 'End-to-end encrypted group. Tap for info.'
                : 'End-to-end encrypted. Tap to verify safety number.',
          ),
          Expanded(child: _buildBody(state, rows, peerTyping)),
          if (_disappearingSeconds > 0)
            Container(
              width: double.infinity,
              color: AppColors.surface,
              padding:
                  const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
              child: Text(
                '⏱ Messages disappear after ${_formatDuration(_disappearingSeconds)}',
                style: const TextStyle(
                  fontSize: 11,
                  color: AppColors.warning,
                ),
              ),
            ),
          _buildComposer(),
        ],
      ),
    );
  }

  Widget _buildBody(AppState state, List<ChatRow> rows, bool peerTyping) {
    if (_loading && rows.isEmpty) {
      return const Center(child: CircularProgressIndicator());
    }
    if (_error != null && rows.isEmpty) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(28),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.lock_outline, size: 42, color: AppColors.danger),
              const SizedBox(height: 12),
              Text(
                _error!,
                textAlign: TextAlign.center,
                style: const TextStyle(color: AppColors.textSecondary),
              ),
              const SizedBox(height: 16),
              OutlinedButton(
                onPressed: _load,
                child: const Text('Try again'),
              ),
            ],
          ),
        ),
      );
    }
    if (rows.isEmpty) {
      return const EmptyThread();
    }

    return ListView.builder(
      controller: _scrollController,
      padding: const EdgeInsets.symmetric(vertical: 10),
      itemCount: rows.length + (peerTyping ? 1 : 0),
      itemBuilder: (_, i) {
        if (i >= rows.length) return const TypingBubble();
        return MessageBubble(
          row: rows[i],
          showTail: i == rows.length - 1,
          onRetry: rows[i].failed ? () => _retry(rows[i]) : null,
          onOpenMedia: rows[i].isMedia
              ? () => _openMedia(rows[i])
              : null,
        );
      },
    );
  }

  Widget _buildComposer() {
    return Container(
      color: AppColors.surface,
      padding: const EdgeInsets.fromLTRB(6, 8, 6, 10),
      child: SafeArea(
        top: false,
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.end,
          children: [
            IconButton(
              icon: const Icon(Icons.attach_file, color: AppColors.textSecondary),
              onPressed: _openAttachmentSheet,
            ),
            Expanded(
              child: TextField(
                controller: _composerController,
                focusNode: _composerFocus,
                minLines: 1,
                maxLines: 5,
                textCapitalization: TextCapitalization.sentences,
                style: const TextStyle(fontSize: 15.5),
                onChanged: _onComposerChanged,
                onSubmitted: (_) => _send(),
                decoration: InputDecoration(
                  hintText: 'Message',
                  isDense: true,
                  fillColor: AppColors.elevated,
                  contentPadding: const EdgeInsets.symmetric(
                    horizontal: 18,
                    vertical: 10,
                  ),
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(22),
                    borderSide: BorderSide.none,
                  ),
                ),
              ),
            ),
            const SizedBox(width: 4),
            ValueListenableBuilder<TextEditingValue>(
              valueListenable: _composerController,
              builder: (context, value, _) {
                final hasText = value.text.trim().isNotEmpty;
                return IconButton(
                  icon: Icon(
                    hasText ? Icons.send : Icons.mic_none,
                    color: hasText
                        ? AppColors.accent
                        : AppColors.textSecondary,
                  ),
                  onPressed: hasText ? _send : null,
                );
              },
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _openAttachmentSheet() async {
    final result = await showModalBottomSheet<Attachment>(
      context: context,
      builder: (_) => const AttachmentSheet(),
    );
    if (result == null || !mounted) return;
    await _sendAttachment(result.bytes, result.name, result.mime, result.kind);
  }

  Future<void> _openMedia(ChatRow row) async {
    try {
      final bytes = await context.read<AppState>().messaging.downloadMedia(row);
      if (!mounted) return;
      await showDialog<void>(
        context: context,
        builder: (_) => MediaViewerDialog(bytes: bytes, name: row.text),
      );
    } catch (_) {
      if (mounted) _toast('This attachment could not be decrypted.');
    }
  }

  Future<void> _retry(ChatRow row) async {
    final state = context.read<AppState>();
    final peer = widget.peerId;
    if (peer == null) return;
    state.chats.removeRow(widget.chatId, row.clientMessageId);
    await state.messaging.sendText(
      chatId: widget.chatId,
      peerId: peer,
      groupId: widget.groupId,
      text: row.text,
      expiresInSeconds: _disappearingSeconds,
    );
    if (mounted) _scrollToBottom();
  }

  void _openSafetyNumber() {
    final peer = widget.peerId;
    if (peer == null) return;
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => SafetyNumberScreen(
          peerId: peer,
          title: widget.title,
        ),
      ),
    );
  }

  void _showGroupInfo() {
    final groupId = widget.groupId;
    if (groupId == null) return;
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => ChatInfoScreen(
          chatId: widget.chatId,
          title: widget.title,
          groupId: groupId,
          isGroup: true,
        ),
      ),
    );
  }

  static String _formatDuration(int seconds) {
    if (seconds < 3600) return '${seconds ~/ 60} min';
    if (seconds < 86400) return '${seconds ~/ 3600} h';
    return '${seconds ~/ 86400} d';
  }
}
