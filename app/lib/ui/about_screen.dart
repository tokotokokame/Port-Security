import 'package:flutter/material.dart';

import '../data/json.dart';
import '../data/repository.dart';
import 'theme.dart';
import 'widgets.dart';

class AboutScreen extends StatelessWidget {
  const AboutScreen({super.key, required this.repo});
  final Repository repo;

  @override
  Widget build(BuildContext context) {
    final m = repo.meta;
    final verified = repo.detailed.where((e) => e.detail!.certainty == '確認済み').length;
    return Scaffold(
      appBar: AppBar(title: const Text('~/about')),
      body: ListView(padding: listPadding(context), children: [
        const TermSection('notice', children: [
          KV('ご利用にあたって', '教育・防御目的の参照ツールです。攻撃手順や攻撃コードは含みません。攻撃ツールは検知に使う痕跡のみを記載しています。'
              '記載は調査の手がかりであり、実環境での判断は一次資料と自組織の手順に従ってください。'),
          KV('通信', 'データはアプリに同梱されており、通信は行いません。リンクは外部ブラウザで開きます。'),
        ]),
        TermSection('data', children: [
          KV('収録', '詳細付き ${repo.detailed.length} 件（確認済み $verified 件） / IANA 登録 ${str(m['iana'])} 件', mono: true),
          KV('最終検証日', str(m['verified']), mono: true),
          KV('ATT&CK', str(m['attack_version']), mono: true),
          KV('IANA 台帳取得日', str(m['iana_fetched']), mono: true),
          const KV('確度', '確認済み: 攻撃・検知の記述に再検証済みの一次資料あり\n一部確認: ポート割当のみ一次資料で確認（不足は各ポートの src タブに表示）'),
        ]),
        TermSection('attribution', children: [
          const KV('MITRE ATT&CK®', '© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.'),
          RuleCard(title: 'ATT&CK Terms of Use', onTap: () => openLink(context, 'https://attack.mitre.org/resources/legal-and-branding/terms-of-use/')),
          const KV('ポート番号', 'IANA Service Name and Transport Protocol Port Number Registry'),
          const KV('検知ルール', 'SigmaHQ (Detection Rule License 1.1) を根拠として参照'),
        ]),
        Padding(
          padding: const EdgeInsets.all(14),
          child: OutlinedButton(
            onPressed: () => showLicensePage(context: context, applicationName: 'Port Security'),
            child: Text('open-source licenses', style: Term.monoStyle(color: Term.teal)),
          ),
        ),
      ]),
    );
  }
}
