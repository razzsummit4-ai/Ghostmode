import 'dart:io';
import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:image_picker/image_picker.dart';
import 'package:path/path.dart' as p;

import 'theme.dart';

/// A file the user chose, still in plaintext on this device.
class Attachment {
  const Attachment(this.bytes, this.name, this.mime, this.kind);
  final Uint8List bytes;
  final String name;
  final String mime;
  final String kind;
}

/// Picker for images, video and documents.
///
/// The chosen file is returned to the caller still in plaintext; it is sealed
/// with AES-256-GCM before anything touches the network, and only the ciphertext
/// is uploaded.
class AttachmentSheet extends StatelessWidget {
  const AttachmentSheet({super.key});

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const SizedBox(height: 10),
          Container(
            width: 38,
            height: 4,
            decoration: BoxDecoration(
              color: AppColors.textSecondary,
              borderRadius: BorderRadius.circular(2),
            ),
          ),
          const SizedBox(height: 16),
          const Text(
            'Send encrypted attachment',
            style: TextStyle(
              fontSize: 15,
              fontWeight: FontWeight.w600,
              color: AppColors.textPrimary,
            ),
          ),
          const SizedBox(height: 4),
          const Padding(
            padding: EdgeInsets.symmetric(horizontal: 24),
            child: Text(
              'The file is encrypted on this device before upload. The file key '
              'travels inside the encrypted message.',
              textAlign: TextAlign.center,
              style: TextStyle(
                fontSize: 12,
                height: 1.4,
                color: AppColors.textSecondary,
              ),
            ),
          ),
          const SizedBox(height: 18),
          _Tile(
            icon: Icons.photo_library_outlined,
            label: 'Photo',
            onTap: () => _pick(context, (b, n, m) => Attachment(b, n, m, 'image')),
          ),
          _Tile(
            icon: Icons.videocam_outlined,
            label: 'Video',
            onTap: () => _pick(
                context, (b, n, m) => Attachment(b, n, m, 'video')),
          ),
          _Tile(
            icon: Icons.insert_drive_file_outlined,
            label: 'Document',
            onTap: () => _pickDocument(context),
          ),
          const SizedBox(height: 10),
        ],
      ),
    );
  }

  Future<void> _pick(
    BuildContext context,
    Attachment Function(Uint8List, String, String) build,
  ) async {
    final picker = ImagePicker();
    final source = await showModalBottomSheet<ImageSource>(
      context: context,
      builder: (_) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const Icon(Icons.camera_alt_outlined),
              title: const Text('Camera'),
              onTap: () => Navigator.of(context).pop(ImageSource.camera),
            ),
            ListTile(
              leading: const Icon(Icons.photo_library_outlined),
              title: const Text('Gallery'),
              onTap: () => Navigator.of(context).pop(ImageSource.gallery),
            ),
          ],
        ),
      ),
    );
    if (source == null || !context.mounted) return;

    try {
      final picked = await picker.pickImage(source: source);
      if (picked == null) return;
      final bytes = await picked.readAsBytes();
      if (!context.mounted) return;
      Navigator.of(context).pop(
        build(bytes, p.basename(picked.path), picked.mimeType ?? 'image/jpeg'),
      );
    } catch (_) {
      if (context.mounted) _toast(context, 'Could not read that file.');
    }
  }

  Future<void> _pickDocument(BuildContext context) async {
    try {
      // file_picker 13.x exposes a fully static API and hands back a URI
      // rather than an in-memory byte buffer, so the file is read from disk
      // here. That read stays on this device: nothing is sent until the caller
      // seals it with AES-256-GCM.
      final file = await FilePicker.pickFile(
        dialogTitle: 'Choose a document',
      );
      final path = file?.path;
      if (path == null || !context.mounted) return;

      final bytes = await File(path).readAsBytes();
      if (bytes.isEmpty || !context.mounted) return;

      Navigator.of(context).pop(
        Attachment(bytes, file!.name, _mimeFor(file.extension), 'file'),
      );
    } catch (_) {
      if (context.mounted) _toast(context, 'Could not read that file.');
    }
  }

  static String _mimeFor(String? extension) => switch (extension?.toLowerCase()) {
        'jpg' || 'jpeg' => 'image/jpeg',
        'png' => 'image/png',
        'gif' => 'image/gif',
        'webp' => 'image/webp',
        'pdf' => 'application/pdf',
        'mp4' => 'video/mp4',
        'mp3' => 'audio/mpeg',
        'txt' => 'text/plain',
        _ => 'application/octet-stream',
      };

  void _toast(BuildContext context, String message) {
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(SnackBar(content: Text(message)));
  }
}

class _Tile extends StatelessWidget {
  const _Tile({required this.icon, required this.label, required this.onTap});

  final IconData icon;
  final String label;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return ListTile(
      leading: Icon(icon, color: AppColors.accent),
      title: Text(label),
      onTap: onTap,
    );
  }
}
