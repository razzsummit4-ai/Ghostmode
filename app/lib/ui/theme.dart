import 'package:flutter/material.dart';

/// WhatsApp-style dark palette for SecureChat.
///
/// The app is dark-only by design. Beyond matching the reference messenger,
/// it avoids emitting bright full-screen surfaces, which both saves OLED power
/// and reduces shoulder-surfing exposure in public.
class AppColors {
  const AppColors._();

  static const background = Color(0xFF0B141A);
  static const surface = Color(0xFF111B21);
  static const appBar = Color(0xFF1F2C34);
  static const elevated = Color(0xFF202C33);
  static const divider = Color(0xFF2A3942);

  static const textPrimary = Color(0xFFE9EDEF);
  static const textSecondary = Color(0xFF8696A0);

  static const accent = Color(0xFF00A884);
  static const accentDark = Color(0xFF005C4B);
  static const linkBlue = Color(0xFF53BDEB);
  static const danger = Color(0xFFF15C6D);
  static const warning = Color(0xFFFFD279);

  static const bubbleMine = Color(0xFF005C4B);
  static const bubbleTheirs = Color(0xFF202C33);

  /// Avatar tints, indexed by the server-assigned avatar colour.
  static const avatarPalette = <Color>[
    Color(0xFF6A7A8C),
    Color(0xFF8E6A5B),
    Color(0xFF5B7A6A),
    Color(0xFF7A6A8E),
    Color(0xFF8E7A5B),
    Color(0xFF5B6E8E),
    Color(0xFF8E5B6A),
    Color(0xFF6A8E5B),
    Color(0xFF5B8E8A),
    Color(0xFF8E6A8E),
    Color(0xFF6A5B8E),
    Color(0xFF7A8E5B),
  ];

  static Color avatarFor(int index) =>
      avatarPalette[index.abs() % avatarPalette.length];
}

/// The single app theme.
ThemeData buildSecureDarkTheme() {
  const scheme = ColorScheme.dark(
    primary: AppColors.accent,
    onPrimary: Colors.white,
    secondary: AppColors.linkBlue,
    surface: AppColors.surface,
    onSurface: AppColors.textPrimary,
    error: AppColors.danger,
  );

  return ThemeData(
    useMaterial3: true,
    brightness: Brightness.dark,
    colorScheme: scheme,
    scaffoldBackgroundColor: AppColors.background,
    appBarTheme: const AppBarTheme(
      backgroundColor: AppColors.appBar,
      foregroundColor: AppColors.textPrimary,
      elevation: 0,
      centerTitle: true,
      titleTextStyle: TextStyle(
        color: AppColors.textPrimary,
        fontSize: 19,
        fontWeight: FontWeight.w600,
      ),
    ),
    dividerTheme: const DividerThemeData(
      color: AppColors.divider,
      thickness: 0.5,
      space: 0.5,
    ),
    listTileTheme: const ListTileThemeData(
      iconColor: AppColors.textSecondary,
      textColor: AppColors.textPrimary,
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: AppColors.elevated,
      hintStyle: const TextStyle(color: AppColors.textSecondary),
      contentPadding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(24),
        borderSide: BorderSide.none,
      ),
    ),
    filledButtonTheme: FilledButtonThemeData(
      style: FilledButton.styleFrom(
        backgroundColor: AppColors.accent,
        foregroundColor: Colors.white,
        minimumSize: const Size.fromHeight(50),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(25),
        ),
        textStyle: const TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        foregroundColor: AppColors.accent,
        side: const BorderSide(color: AppColors.accent),
        minimumSize: const Size.fromHeight(50),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(25),
        ),
      ),
    ),
    snackBarTheme: const SnackBarThemeData(
      backgroundColor: AppColors.elevated,
      contentTextStyle: TextStyle(color: AppColors.textPrimary),
      behavior: SnackBarBehavior.floating,
    ),
    dialogTheme: const DialogThemeData(
      backgroundColor: AppColors.surface,
      titleTextStyle: TextStyle(
        color: AppColors.textPrimary,
        fontSize: 18,
        fontWeight: FontWeight.w600,
      ),
      contentTextStyle: TextStyle(color: AppColors.textPrimary),
    ),
    bottomSheetTheme: const BottomSheetThemeData(
      backgroundColor: AppColors.surface,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
    ),
  );
}

/// The trust banner shown at the top of every chat.
///
/// It is a claim the app must keep honest, so it lives in one shared widget
/// rather than being retyped across screens.
class EncryptionBanner extends StatelessWidget {
  const EncryptionBanner({super.key, required this.onTap, this.subtitle});

  final VoidCallback onTap;
  final String? subtitle;

  @override
  Widget build(BuildContext context) {
    return Material(
      color: AppColors.surface,
      child: InkWell(
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 9),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(Icons.lock, size: 13, color: AppColors.warning),
              const SizedBox(width: 6),
              Flexible(
                child: Text(
                  subtitle ?? 'End-to-end encrypted. Tap for info.',
                  textAlign: TextAlign.center,
                  style: const TextStyle(
                    fontSize: 12.5,
                    color: AppColors.warning,
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

/// Circular avatar with an initial, tinted by a stable per-contact colour.
class ContactAvatar extends StatelessWidget {
  const ContactAvatar({
    super.key,
    required this.name,
    this.colorIndex = 0,
    this.radius = 24,
  });

  final String name;
  final int colorIndex;
  final double radius;

  @override
  Widget build(BuildContext context) {
    final trimmed = name.trim();
    final initial = trimmed.isEmpty ? '?' : trimmed[0].toUpperCase();
    return CircleAvatar(
      radius: radius,
      backgroundColor: AppColors.avatarFor(colorIndex),
      child: Text(
        initial,
        style: TextStyle(
          fontSize: radius * 0.8,
          fontWeight: FontWeight.w600,
          color: Colors.white,
        ),
      ),
    );
  }
}

/// A small pill used for key state, e.g. "100 pre-keys".
class StatusPill extends StatelessWidget {
  const StatusPill({
    super.key,
    required this.label,
    this.color = AppColors.textSecondary,
    this.icon,
  });

  final String label;
  final Color color;
  final IconData? icon;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (icon != null) ...[
            Icon(icon, size: 12, color: color),
            const SizedBox(width: 4),
          ],
          Text(label, style: TextStyle(fontSize: 11.5, color: color)),
        ],
      ),
    );
  }
}
