import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:port_security/data/repository.dart';
import 'package:port_security/main.dart';

void main() {
  late PortRepository repo;
  setUpAll(() => repo = PortRepository.fromJsonString(File('assets/data/port_index.json').readAsStringSync()));

  Future<void> start(WidgetTester tester) async {
    await tester.pumpWidget(PortSecurityApp(repository: repo));
    await tester.pumpAndSettle();
  }

  testWidgets('search -> detail shows the full chain', (tester) async {
    await start(tester);
    expect(find.text('ポート検索'), findsOneWidget);
    expect(find.text('51 件'), findsOneWidget);

    await tester.enterText(find.byKey(const Key('search-field')), '3389');
    await tester.pumpAndSettle();
    expect(find.text('2 件'), findsOneWidget);

    await tester.tap(find.text('3389/TCP  ms-wbt-server'));
    await tester.pumpAndSettle();
    expect(find.text('Remote Desktop Protocol (RDP TCP)'), findsOneWidget);
    for (final title in ['MITRE ATT&CK', '検知・ログ調査', '根拠資料']) {
      await tester.scrollUntilVisible(find.text(title), 300, scrollable: find.byType(Scrollable).first);
      expect(find.text(title), findsOneWidget);
    }
  });

  testWidgets('no result message', (tester) async {
    await start(tester);
    await tester.enterText(find.byKey(const Key('search-field')), 'zzzz-no-such');
    await tester.pumpAndSettle();
    expect(find.text('該当するポートはありません'), findsOneWidget);
  });

  testWidgets('attack tab lists patterns and opens ports', (tester) async {
    await start(tester);
    await tester.tap(find.text('攻撃手法'));
    await tester.pumpAndSettle();
    expect(find.text('攻撃手法から探す'), findsOneWidget);
    await tester.tap(find.textContaining('ブルートフォース').first);
    await tester.pumpAndSettle();
    expect(find.textContaining('対象ポート'), findsOneWidget);
  });

  testWidgets('about screen opens', (tester) async {
    await start(tester);
    await tester.tap(find.byTooltip('このアプリについて'));
    await tester.pumpAndSettle();
    expect(find.text('ご利用にあたって'), findsOneWidget);
  });
}
