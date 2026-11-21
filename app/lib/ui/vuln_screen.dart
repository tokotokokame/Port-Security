import 'package:flutter/material.dart';

import '../data/models.dart';
import '../data/repository.dart';
import 'kb_screens.dart';
import 'theme.dart';
import 'widgets.dart';

/// One CVE line for a port's risk: condition first, because a port number alone never confirms a CVE.
class VulnCard extends StatelessWidget {
  const VulnCard(this.v, this.repo, {super.key});
  final Vuln v;
  final Repository repo;

  @override
  Widget build(BuildContext context) => RuleCard(
        title: '${v.id}  CVSS ${v.score}',
        trailing: v.kev ? 'KEV' : '',
        subtitle: '条件: ${v.condition}',
        onTap: () => push(context, VulnDetailScreen(v, repo)),
      );
}

class VulnDetailScreen extends StatelessWidget {
  const VulnDetailScreen(this.v, this.repo, {super.key});
  final Vuln v;
  final Repository repo;

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(title: Text('~/cve/${v.id}', overflow: TextOverflow.ellipsis)),
        body: ListView(padding: listPadding(context), children: [
          TermSection(v.id, note: v.kev ? 'CISA KEV 掲載 ${v.kevAdded}' : 'KEV 未掲載', children: [
            KV('題名', v.title),
            KV('該当条件', v.condition),
            const KV('注意', 'ポート番号だけでは該当を判定できません。製品・バージョン・構成を確認してください。'),
            KV('公開 / 更新', '${v.published} / ${v.updated}', mono: true),
          ]),
          TermSection('cvss', children: [
            for (final (score, ver, src, vec) in v.cvss) RuleCard(title: '$score  (v$ver)', trailing: src, subtitle: vec),
          ]),
          TermSection('affected', note: '${v.affected.length}', children: [
            for (final (vendor, product, versions, fixed) in v.affected)
              RuleCard(title: '$vendor $product', children: [
                for (final x in versions) Bullet(x, color: Term.text),
                if (fixed.isNotEmpty) Bullet('修正: ${fixed.join(', ')}', color: Term.green),
              ]),
          ]),
          ReviewSection(certainty: '確認済み', verified: v.verified, notes: v.notes),
          TermSection('refs', children: [for (final u in v.refs) RuleCard(title: u, onTap: () => openLink(context, u))]),
          TermSection('sources', children: [for (final id in v.sources) SourceRow(id, repo)]),
        ]),
      );
}
