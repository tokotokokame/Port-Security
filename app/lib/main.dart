import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_localizations/flutter_localizations.dart';

import 'data/repository.dart';
import 'ui/home_shell.dart';
import 'ui/theme.dart';

void main() {
  LicenseRegistry.addLicense(() async* {
    yield LicenseEntryWithLineBreaks(const ['Noto Sans JP'], await rootBundle.loadString('assets/fonts/OFL.txt'));
    yield LicenseEntryWithLineBreaks(const ['JetBrains Mono'], await rootBundle.loadString('assets/fonts/JetBrainsMono-OFL.txt'));
    yield const LicenseEntryWithLineBreaks(['MITRE ATT&CK'],
        '© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.\n\n'
        'Terms of Use: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/');
  });
  runApp(const PortSecurityApp());
}

class PortSecurityApp extends StatefulWidget {
  /// [repository] is injectable for tests; otherwise the bundled assets are loaded.
  const PortSecurityApp({super.key, this.repository});
  final Repository? repository;

  @override
  State<PortSecurityApp> createState() => _PortSecurityAppState();
}

class _PortSecurityAppState extends State<PortSecurityApp> {
  late final Future<Repository> _repo = widget.repository != null ? Future.value(widget.repository) : Repository.load();

  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'Port Security',
        debugShowCheckedModeBanner: false,
        theme: Term.theme(),
        // Japanese locale keeps kanji in Japanese glyph forms.
        locale: const Locale('ja', 'JP'),
        supportedLocales: const [Locale('ja', 'JP')],
        localizationsDelegates: GlobalMaterialLocalizations.delegates,
        home: FutureBuilder<Repository>(
          future: _repo,
          builder: (context, snap) {
            if (snap.hasError) {
              if (kDebugMode) debugPrint('data load failed: ${snap.error}');
              return const Scaffold(body: Center(child: Text('データを読み込めませんでした。\nアプリを再インストールしてください。', textAlign: TextAlign.center)));
            }
            if (!snap.hasData) return const Scaffold(body: Center(child: CircularProgressIndicator()));
            return HomeShell(repo: snap.data!);
          },
        ),
      );
}
