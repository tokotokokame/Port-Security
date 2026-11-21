import 'package:flutter/material.dart';

import '../data/models.dart';
import 'widgets.dart';

class PortDetailScreen extends StatelessWidget {
  const PortDetailScreen({super.key, required this.entry});
  final PortEntry entry;

  @override
  Widget build(BuildContext context) {
    final e = entry;
    final logs = [...e.logs]..sort((a, b) => a.rank.compareTo(b.rank));
    final t = Theme.of(context).textTheme;
    return Scaffold(
      appBar: AppBar(title: Text('${e.label}  ${e.service}')),
      body: ListView(padding: EdgeInsets.only(bottom: 24 + MediaQuery.paddingOf(context).bottom), children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 4),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(e.formalName, style: t.titleLarge?.copyWith(fontWeight: FontWeight.bold)),
            const SizedBox(height: 8),
            Wrap(spacing: 8, runSpacing: 6, children: [
              RiskPill(e.risk),
              Pill('確度: ${e.certainty}',
                  color: e.certainty == '確認済み' ? Colors.green.shade700 : Colors.orange.shade800),
            ]),
          ]),
        ),
        Section('概要', icon: Icons.description_outlined, children: [
          Field('目的', e.purpose),
          Field('技術的な仕組み', e.technical),
          Field('正常な利用例', e.normalUse),
        ]),
        Section('攻撃の特徴', icon: Icons.warning_amber_outlined, children: [
          Field('悪用例', e.malicious),
          Field('不審な通信の兆候', e.suspicious),
          if (e.risk != null) ...[
            Field('狙われる理由', e.risk!.reason),
            Field('不審な兆候（リスク評価）', e.risk!.indicators),
          ],
        ]),
        Section('攻撃手法', icon: Icons.gpp_maybe_outlined, children: [
          for (final a in e.attacks)
            ExpansionTile(
              tilePadding: EdgeInsets.zero,
              title: Text(a.name),
              subtitle: Text(a.id),
              childrenPadding: const EdgeInsets.only(bottom: 8),
              children: [Field('特徴', a.features), Field('検知方法', a.detection), Field('対策', a.defenses)],
            ),
        ]),
        Section('MITRE ATT&CK', icon: Icons.hub_outlined, children: [
          for (final tq in e.techniques)
            ListTile(
              contentPadding: EdgeInsets.zero,
              title: Text('${tq.id}  ${tq.name}'),
              subtitle: Text([
                tq.tactics.join(' / '),
                for (final d in tq.detections) '検知戦略 ${d.id}: ${d.name}',
              ].where((s) => s.isNotEmpty).join('\n')),
              trailing: const Icon(Icons.open_in_new, size: 18),
              onTap: () => openLink(context, tq.url),
            ),
        ]),
        Section('検知・ログ調査', icon: Icons.manage_search, children: [
          Field('確認ポイント', e.checkpoints),
          if (e.risk != null) Field('調査の焦点（リスク評価）', e.risk!.focus),
          for (final l in logs)
            ExpansionTile(
              tilePadding: EdgeInsets.zero,
              initiallyExpanded: l.rank == 0,
              title: Text(l.platform),
              subtitle: Text('関連度: ${l.match}'),
              childrenPadding: const EdgeInsets.only(bottom: 8),
              children: [
                Field('検知ロジック', l.analytics),
                Field('調査手順', l.procedure),
                Field('紐付けの根拠', l.via.join(', ')),
                Field('確度', l.certainty),
              ],
            ),
        ]),
        Section('推奨対策', icon: Icons.shield_outlined, children: [
          Field('対策', e.defenses),
          if (e.risk != null) Field('緩和策（リスク評価）', e.risk!.mitigation),
        ]),
        Section('根拠資料', icon: Icons.menu_book_outlined, children: [
          for (final s in e.sources)
            ListTile(
              contentPadding: EdgeInsets.zero,
              dense: true,
              title: Text(s.name.isEmpty ? s.id : s.name),
              subtitle: Text(s.url, maxLines: 1, overflow: TextOverflow.ellipsis),
              trailing: const Icon(Icons.open_in_new, size: 18),
              onTap: () => openLink(context, s.url),
            ),
        ]),
        Section('確度と未整備の情報', icon: Icons.fact_check_outlined, children: [
          Field('確認日', e.verifiedDate),
          Field('未確認事項', e.notes),
          Field('未整備', e.gaps.join('\n')),
        ]),
      ]),
    );
  }
}
