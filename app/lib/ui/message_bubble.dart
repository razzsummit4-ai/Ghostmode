import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

import '../state/chat_store.dart';
import 'theme.dart';

/// One message bubble.
///
/// Every outgoing bubble carries a padlock: it is the visible claim that the
/// text was sealed on this device, and it stays true because [ChatRow] only
/// ever holds text this device produced or decrypted.
class MessageBubble extends StatelessWidget {
  const MessageBubble({
    super.key,
    required this.row,
    this.showTail = true,
    this.onRetry,
    this.onOpenMedia,
  });

  final ChatRow row;
  final bool showTail;
  final VoidCallback? onRetry;
  final VoidCallback? onOpenMedia;

  @override
  Widget build(BuildContext context) {
    final isMine = row.isMine;
    final failed = row.failed;

    final bubble = Container(
      constraints: BoxConstraints(
        maxWidth: MediaQuery.of(context).size.width * 0.78,
      ),
      margin: EdgeInsets.only(
        left: isMine ? 56 : 12,
        right: isMine ? 12 : 56,
        top: 2,
        bottom: showTail ? 6 : 2,
      ),
      padding: const EdgeInsets.fromLTRB(11, 7, 9, 5),
      decoration: BoxDecoration(
        color: failed
            ? AppColors.danger.withValues(alpha: 0.18)
            : isMine
                ? AppColors.bubbleMine
                : AppColors.bubbleTheirs,
        borderRadius: BorderRadius.only(
          topLeft: const Radius.circular(14),
          topRight: const Radius.circular(14),
          bottomLeft: Radius.circular(showTail ? (isMine ? 14 : 4) : 14),
          bottomRight: Radius.circular(showTail ? (isMine ? 4 : 14) : 14),
        ),
        border: row.kind == 'undecryptable'
            ? Border.all(color: AppColors.danger.withValues(alpha: 0.6))
            : null,
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.end,
        mainAxisSize: MainAxisSize.min,
        children: [
          if (row.kind == 'expired')
            const Padding(
              padding: EdgeInsets.only(bottom: 4),
              child: Text(
                'This message expired',
                style: TextStyle(
                  fontSize: 13.5,
                  fontStyle: FontStyle.italic,
                  color: AppColors.textSecondary,
                ),
              ),
            )
          else
            GestureDetector(
              onTap: onOpenMedia,
              child: Text(
                row.text,
                style: TextStyle(
                  fontSize: 15.5,
                  height: 1.3,
                  color: row.kind == 'undecryptable'
                      ? AppColors.warning
                      : AppColors.textPrimary,
                ),
              ),
            ),
          const SizedBox(height: 2),
          _Meta(row: row, isMine: isMine, failed: failed, onRetry: onRetry),
        ],
      ),
    );

    return Align(
      alignment: isMine ? Alignment.centerRight : Alignment.centerLeft,
      child: bubble,
    );
  }
}

/// Timestamp, padlock, and delivery ticks.
class _Meta extends StatelessWidget {
  const _Meta({
    required this.row,
    required this.isMine,
    required this.failed,
    this.onRetry,
  });

  final ChatRow row;
  final bool isMine;
  final bool failed;
  final VoidCallback? onRetry;

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        if (failed)
          GestureDetector(
            onTap: onRetry,
            child: const Padding(
              padding: EdgeInsets.only(right: 5),
              child: Icon(Icons.error_outline, size: 13, color: AppColors.danger),
            ),
          )
        else
          const Padding(
            padding: EdgeInsets.only(right: 4),
            child: Icon(Icons.lock, size: 10, color: Colors.white54),
          ),
        Text(
          DateFormat.jm().format(row.createdAt),
          style: const TextStyle(fontSize: 10.5, color: Colors.white54),
        ),
        if (isMine) ...[
          const SizedBox(width: 4),
          Icon(
            switch (row.status) {
              'read' || 'delivered' => Icons.done_all,
              'sending' => Icons.schedule,
              'failed' => Icons.error_outline,
              _ => Icons.done,
            },
            size: 14,
            color: switch (row.status) {
              'read' => AppColors.linkBlue,
              'failed' => AppColors.danger,
              _ => Colors.white54,
            },
          ),
        ],
      ],
    );
  }
}

/// The animated "…" shown while a peer is typing.
class TypingBubble extends StatefulWidget {
  const TypingBubble({super.key});

  @override
  State<TypingBubble> createState() => _TypingBubbleState();
}

class _TypingBubbleState extends State<TypingBubble>
    with SingleTickerProviderStateMixin {
  late final AnimationController _controller = AnimationController(
    vsync: this,
    duration: const Duration(milliseconds: 1100),
  )..repeat();

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Align(
      alignment: Alignment.centerLeft,
      child: Container(
        margin: const EdgeInsets.only(left: 12, right: 56, top: 2, bottom: 6),
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
        decoration: const BoxDecoration(
          color: AppColors.bubbleTheirs,
          borderRadius: BorderRadius.only(
            topLeft: Radius.circular(14),
            topRight: Radius.circular(14),
            bottomRight: Radius.circular(14),
            bottomLeft: Radius.circular(4),
          ),
        ),
        child: AnimatedBuilder(
          animation: _controller,
          builder: (_, __) => Row(
            mainAxisSize: MainAxisSize.min,
            children: List.generate(3, (i) {
              final t = (_controller.value * 3 - i).clamp(0.0, 1.0);
              final lift = (t < 0.5 ? t : 1 - t) * 4;
              return Padding(
                padding: EdgeInsets.only(
                  right: i == 2 ? 0 : 4,
                  bottom: lift,
                ),
                child: Container(
                  width: 6,
                  height: 6,
                  decoration: const BoxDecoration(
                    color: AppColors.textSecondary,
                    shape: BoxShape.circle,
                  ),
                ),
              );
            }),
          ),
        ),
      ),
    );
  }
}

/// Shown when a thread has no messages yet.
class EmptyThread extends StatelessWidget {
  const EmptyThread({super.key});

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.lock_outline, size: 44, color: AppColors.accent),
            const SizedBox(height: 14),
            const Text(
              'No messages yet',
              style: TextStyle(
                fontSize: 16,
                fontWeight: FontWeight.w600,
                color: AppColors.textPrimary,
              ),
            ),
            const SizedBox(height: 8),
            const Text(
              'Messages you send are encrypted on this device with a key the '
              'server never receives.',
              textAlign: TextAlign.center,
              style: TextStyle(
                fontSize: 13,
                height: 1.5,
                color: AppColors.textSecondary,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

/// Full-screen viewer for a decrypted attachment.
class MediaViewerDialog extends StatelessWidget {
  const MediaViewerDialog({super.key, required this.bytes, required this.name});

  final Uint8List bytes;
  final String name;

  @override
  Widget build(BuildContext context) {
    return Dialog(
      backgroundColor: Colors.transparent,
      insetPadding: const EdgeInsets.all(12),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Flexible(
            child: ClipRRect(
              borderRadius: BorderRadius.circular(12),
              child: Image.memory(
                bytes,
                fit: BoxFit.contain,
                errorBuilder: (_, __, ___) => Container(
                  height: 180,
                  color: AppColors.elevated,
                  alignment: Alignment.center,
                  child: Text(
                    'Decrypted $name\n(${bytes.length} bytes)',
                    textAlign: TextAlign.center,
                    style: const TextStyle(color: AppColors.textSecondary),
                  ),
                ),
              ),
            ),
          ),
          const SizedBox(height: 12),
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }

}
