import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_localizations/flutter_localizations.dart';

import 'data/repository.dart';
import 'ui/home_shell.dart';

void main() {
  LicenseRegistry.addLicense(() async* {
    final ofl = await rootBundle.loadString('assets/fonts/OFL.txt');
    yield LicenseEntryWithLineBreaks(const ['Noto Sans JP'], ofl);
    yield const LicenseEntryWithLineBreaks(['MITRE ATT&CK'],
        '© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.\n\n'
        'Terms of Use: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/');
  });
  runApp(const PortSecurityApp());
}

class PortSecurityApp extends StatefulWidget {
  /// [repository] is injectable for tests; otherwise the bundled asset is loaded.
  const PortSecurityApp({super.key, this.repository});
  final PortRepository? repository;

  @override
  State<PortSecurityApp> createState() => _PortSecurityAppState();
}

class _PortSecurityAppState extends State<PortSecurityApp> {
  late final Future<PortRepository> _repo =
      widget.repository != null ? Future.value(widget.repository) : PortRepository.load();

  ThemeData _theme(Brightness b) => ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFF00897B), brightness: b),
        fontFamily: 'NotoSansJP',
        useMaterial3: true,
      );

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Port Security',
      debugShowCheckedModeBanner: false,
      theme: _theme(Brightness.light),
      darkTheme: _theme(Brightness.dark),
      // Japanese locale keeps kanji in Japanese glyph forms (not Chinese).
      locale: const Locale('ja', 'JP'),
      supportedLocales: const [Locale('ja', 'JP')],
      localizationsDelegates: GlobalMaterialLocalizations.delegates,
      home: FutureBuilder<PortRepository>(
        future: _repo,
        builder: (context, snap) {
          if (snap.hasError) {
            if (kDebugMode) debugPrint('data load failed: ${snap.error}');
            return const Scaffold(body: Center(child: Text('データを読み込めませんでした。\nアプリを再インストールしてください。', textAlign: TextAlign.center)));
          }
          if (!snap.hasData) return const Scaffold(body: Center(child: CircularProgressIndicator()));
          return HomeShell(repository: snap.data!);
        },
      ),
    );
  }
}
