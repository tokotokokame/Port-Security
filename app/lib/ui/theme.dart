import 'package:flutter/material.dart';

/// Terminal palette (dark only). Text colours meet 4.5:1 on [bg].
abstract final class Term {
  static const bg = Color(0xFF0B0F14);
  static const panel = Color(0xFF0F141A);
  static const field = Color(0xFF11161D);
  static const line = Color(0xFF222B36);
  static const text = Color(0xFFC9D1D9);
  static const bright = Color(0xFFE6EDF3);
  static const dim = Color(0xFF8B949E);
  static const green = Color(0xFF3FB950);
  static const teal = Color(0xFF2DD4BF);
  static const amber = Color(0xFFD29922);
  static const red = Color(0xFFF85149);
  static const orange = Color(0xFFDB6D28);
  static const mono = 'JetBrainsMono';
  static const jp = 'NotoSansJP';

  static Color risk(String level) => switch (level) {
        'Critical' => red,
        'High' => orange,
        'Medium' => amber,
        'Low' => green,
        _ => dim,
      };

  static TextStyle monoStyle({double size = 12, Color color = text, FontWeight weight = FontWeight.w400}) =>
      TextStyle(fontFamily: mono, fontFamilyFallback: const [jp], fontSize: size, color: color, fontWeight: weight, height: 1.4);

  static ThemeData theme() {
    final base = ThemeData(brightness: Brightness.dark, useMaterial3: true, fontFamily: jp);
    return base.copyWith(
      scaffoldBackgroundColor: bg,
      colorScheme: const ColorScheme.dark(primary: teal, secondary: green, surface: panel, error: red, onSurface: text),
      appBarTheme: AppBarTheme(backgroundColor: bg, foregroundColor: text, elevation: 0, scrolledUnderElevation: 0,
          titleTextStyle: monoStyle(size: 14, color: green, weight: FontWeight.w700)),
      dividerTheme: const DividerThemeData(color: line, space: 1, thickness: 1),
      textTheme: base.textTheme.apply(bodyColor: text, displayColor: bright, fontFamilyFallback: const [mono]),
      inputDecorationTheme: const InputDecorationTheme(
        filled: true, fillColor: field, isDense: true,
        border: OutlineInputBorder(borderSide: BorderSide(color: line)),
        enabledBorder: OutlineInputBorder(borderSide: BorderSide(color: line)),
        focusedBorder: OutlineInputBorder(borderSide: BorderSide(color: teal)),
      ),
      navigationBarTheme: NavigationBarThemeData(
        backgroundColor: panel, indicatorColor: teal.withValues(alpha: 0.18), height: 60,
        labelTextStyle: WidgetStatePropertyAll(monoStyle(size: 11)),
      ),
      tabBarTheme: TabBarThemeData(labelColor: teal, unselectedLabelColor: dim, indicatorColor: teal,
          labelStyle: monoStyle(size: 12, weight: FontWeight.w700), unselectedLabelStyle: monoStyle(size: 12),
          dividerColor: line, tabAlignment: TabAlignment.start),
      snackBarTheme: SnackBarThemeData(backgroundColor: field, contentTextStyle: monoStyle(color: bright)),
    );
  }
}
