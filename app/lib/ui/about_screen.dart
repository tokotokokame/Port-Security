import 'package:flutter/material.dart';

import '../data/repository.dart';
import 'widgets.dart';

class AboutScreen extends StatelessWidget {
  const AboutScreen({super.key, required this.repository});
  final PortRepository repository;

  @override
  Widget build(BuildContext context) {
    final ports = repository.ports;
    final latest = ports.map((p) => p.verifiedDate).fold('', (a, b) => b.compareTo(a) > 0 ? b : a);
    final confirmed = ports.where((p) => p.certainty == '確認済み').length;
    return Scaffold(
      appBar: AppBar(title: const Text('このアプリについて')),
      body: ListView(padding: const EdgeInsets.only(bottom: 24), children: [
        const Section('ご利用にあたって', icon: Icons.gavel_outlined, children: [
          Text('本アプリは教育・防御目的の参照ツールです。攻撃手順や攻撃コードは含みません。'
              '記載内容は調査の手がかりであり、実環境での判断は一次資料と自組織の手順に従ってください。'),
        ]),
        Section('データ', icon: Icons.dataset_outlined, children: [
          Field('収録ポート', '${ports.length} 件（確認済み $confirmed 件）'),
          Field('最終検証日', latest),
          const Field('確度の意味', '確認済み: 攻撃・検知の記述に一次資料あり\n一部確認: ポート割当のみ一次資料で確認（不足は各ポートの「未整備」に表示）'),
          const Field('通信', 'データはアプリに同梱されており、通信は行いません。リンクはブラウザで開きます。'),
        ]),
        Section('出典・帰属', icon: Icons.menu_book_outlined, children: [
          const Field('MITRE ATT&CK®',
              '© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.'),
          ListTile(
            contentPadding: EdgeInsets.zero,
            title: const Text('ATT&CK 利用規約'),
            trailing: const Icon(Icons.open_in_new, size: 18),
            onTap: () => openLink(context, 'https://attack.mitre.org/resources/legal-and-branding/terms-of-use/'),
          ),
          const Field('ポート番号', 'IANA Service Name and Transport Protocol Port Number Registry'),
        ]),
        Padding(
          padding: const EdgeInsets.all(12),
          child: OutlinedButton.icon(
            icon: const Icon(Icons.article_outlined),
            label: const Text('オープンソースライセンス'),
            onPressed: () => showLicensePage(context: context, applicationName: 'Port Security'),
          ),
        ),
      ]),
    );
  }
}
