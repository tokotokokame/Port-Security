import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:port_security/data/repository.dart';
import 'package:port_security/main.dart';
import 'package:port_security/ui/kb_screens.dart';
import 'package:port_security/ui/port_detail_screen.dart';
import 'package:port_security/ui/search_screen.dart';
import 'package:port_security/ui/theme.dart';

import 'repository_test.dart' show loadRepo;

void main() {
  late Repository repo;
  setUpAll(() => repo = loadRepo());

  Future<void> start(WidgetTester tester) async {
    tester.view.physicalSize = const Size(1080, 2340);
    tester.view.devicePixelRatio = 2.75;
    addTearDown(tester.view.reset);
    await tester.pumpWidget(PortSecurityApp(repository: repo));
    await tester.pumpAndSettle();
  }

  testWidgets('search -> detail -> tabs', (tester) async {
    await start(tester);
    expect(find.text('port-security'), findsOneWidget);
    await tester.enterText(find.byKey(const Key('search-field')), '445/tcp');
    await tester.pumpAndSettle();
    expect(find.textContaining('1 hits'), findsOneWidget);
    await tester.tap(find.byType(PortRow).first); // not the search field, which also shows '445/tcp'
    await tester.pumpAndSettle();
    for (final tab in ['攻撃', 'tools', 'att&ck', 'logs', 'src']) {
      await tester.tap(find.text(tab));
      await tester.pumpAndSettle();
    }
    expect(find.textContaining('# sources'), findsOneWidget);
  });

  testWidgets('detailed search panel toggles and filters', (tester) async {
    await start(tester);
    expect(find.text('-- 基本'), findsNothing);
    await tester.tap(find.byKey(const Key('filter-toggle')));
    await tester.pumpAndSettle();
    expect(find.text('-- 基本'), findsOneWidget);
    await tester.tap(find.text('詳細ありのみ'));
    await tester.pumpAndSettle();
    // the expanded panel pushes the hit counter below the fold
    await tester.scrollUntilVisible(find.textContaining('160 hits'), 200, scrollable: find.byType(Scrollable).first);
    expect(find.textContaining('160 hits'), findsOneWidget);
    expect(find.byKey(const Key('filter-count')), findsOneWidget);
    await tester.ensureVisible(find.text('reset')); // built but scrolled off-screen
    await tester.pumpAndSettle();
    await tester.tap(find.text('reset'));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('filter-count')), findsNothing);
  });

  testWidgets('IANA-only entry opens with registry info', (tester) async {
    await start(tester);
    final e = repo.entries.firstWhere((e) => e.detail == null);
    await tester.pumpWidget(MaterialApp(theme: Term.theme(), home: PortDetailScreen(entry: e, repo: repo)));
    await tester.pumpAndSettle();
    expect(find.text('詳細未整備'), findsOneWidget);
  });

  testWidgets('bottom tabs: attacks, tools, logs', (tester) async {
    await start(tester);
    await tester.tap(find.text('tools'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Impacket'));
    await tester.pumpAndSettle();
    expect(find.textContaining('# artifacts'), findsOneWidget);
    await tester.tap(find.byType(BackButton)); // pageBack() looks for the English 'Back' tooltip
    await tester.pumpAndSettle();
    await tester.tap(find.text('logs'));
    await tester.pumpAndSettle();
    expect(find.textContaining('Hyper-V'), findsWidgets);
  });

  testWidgets('v1.1: risk shows CVE with condition; CVE screen opens', (tester) async {
    await start(tester);
    await tester.enterText(find.byKey(const Key('search-field')), '445/tcp');
    await tester.pumpAndSettle();
    await tester.tap(find.byType(PortRow).first);
    await tester.pumpAndSettle();
    final card = find.textContaining('CVE-2017-0144');
    await tester.dragUntilVisible(card, find.byType(ListView).first, const Offset(0, -300));
    await tester.pumpAndSettle();
    expect(find.textContaining('条件:'), findsWidgets);
    await tester.tap(card);
    await tester.pumpAndSettle();
    expect(find.text('~/cve/CVE-2017-0144'), findsOneWidget);
    expect(find.textContaining('ポート番号だけでは該当を判定できません'), findsOneWidget);
  });

  testWidgets('v1.1: attack detail shows certainty and review date', (tester) async {
    final a = repo.attacks.values.first;
    await tester.pumpWidget(MaterialApp(theme: Term.theme(), home: AttackDetailScreen(a, repo)));
    await tester.pumpAndSettle();
    expect(find.text('確度'), findsOneWidget);
    expect(find.text('最終確認日'), findsOneWidget);
  });

  testWidgets('lists keep clear of the system navigation bar', (tester) async {
    final e = repo.detailed.first;
    await tester.pumpWidget(MaterialApp(theme: Term.theme(),
        home: MediaQuery(data: const MediaQueryData(padding: EdgeInsets.only(bottom: 40)), child: PortDetailScreen(entry: e, repo: repo))));
    await tester.pumpAndSettle();
    final list = tester.widget<ListView>(find.byType(ListView).first);
    expect((list.padding as EdgeInsets).bottom, 64);
  });
}
