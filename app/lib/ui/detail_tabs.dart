import 'package:flutter/material.dart';

import '../data/models.dart';
import '../data/repository.dart';
import 'kb_screens.dart';
import 'theme.dart';
import 'widgets.dart';

ListView _tab(BuildContext context, List<Widget> children) => ListView(padding: listPadding(context), children: children);

class IanaOnlyTab extends StatelessWidget {
  const IanaOnlyTab(this.e, {super.key});
  final PortEntry e;

  @override
  Widget build(BuildContext context) => _tab(context, [
        TermSection('iana', children: [
          KV('サービス名', e.service, mono: true),
          KV('説明 (IANA)', e.iana),
          KV('非公認利用の報告 (IANA)', e.unauthorized),
          const KV('詳細', 'このポートは IANA 登録情報のみ収録しています。攻撃・検知・ログの詳細は未整備です。'),
        ]),
      ]);
}

class OverviewTab extends StatelessWidget {
  const OverviewTab(this.e, this.repo, {super.key});
  final PortEntry e;
  final Repository repo;

  @override
  Widget build(BuildContext context) {
    final d = e.detail!;
    final r = d.risk;
    return _tab(context, [
      TermSection('overview', children: [
        KV('分類', d.category, mono: true), KV('用途', d.purpose), KV('仕組み', d.technical), KV('正常な利用例', d.normal),
        KV('IANA 登録名', e.service, mono: true), KV('IANA 説明', e.iana), KV('非公認利用の報告 (IANA)', e.unauthorized),
      ]),
      if (r != null)
        TermSection('risk', note: r.level, children: [
          KV('狙われる理由', r.reason), KV('不審な兆候', r.indicators), KV('調査の焦点', r.focus), KV('緩和策', r.mitigation),
        ]),
      TermSection('defense', children: [KV('推奨対策', d.defenses)]),
    ]);
  }
}

class AttackTab extends StatelessWidget {
  const AttackTab(this.d, this.repo, {super.key});
  final Detail d;
  final Repository repo;

  @override
  Widget build(BuildContext context) => _tab(context, [
        TermSection('features', children: [KV('悪用例', d.malicious), KV('不審な通信の兆候', d.suspicious)]),
        TermSection('attacks', note: '${d.attacks.length}', children: [
          for (final id in d.attacks)
            if (repo.attacks[id] case final a?)
              RuleCard(title: a.name, trailing: a.category, subtitle: a.detection, onTap: () => push(context, AttackDetailScreen(a, repo))),
        ]),
      ]);
}

class ToolsTab extends StatelessWidget {
  const ToolsTab(this.d, this.repo, {super.key});
  final Detail d;
  final Repository repo;

  @override
  Widget build(BuildContext context) => _tab(context, [
        TermSection('tools', note: '検知視点（痕跡）', children: [
          if (d.tools.isEmpty) Text('このポートに紐付く攻撃ツールは未登録です', style: Term.monoStyle(color: Term.dim)),
          for (final id in d.tools)
            if (repo.tools[id] case final t?)
              RuleCard(title: t.name, trailing: t.sid ?? '', onTap: () => push(context, ToolDetailScreen(t, repo)),
                  children: [for (final a in t.artifacts.take(2)) Bullet(a, color: Term.dim)]),
        ]),
      ]);
}

class AttackMatrixTab extends StatelessWidget {
  const AttackMatrixTab(this.d, this.repo, {super.key});
  final Detail d;
  final Repository repo;

  @override
  Widget build(BuildContext context) => _tab(context, [
        TermSection('att&ck', note: 'MITRE ATT&CK', children: [
          for (final id in d.techniques)
            if (repo.techniques[id] case final t?) TechniqueCard(t, repo),
        ]),
      ]);
}

class LogsTab extends StatelessWidget {
  const LogsTab(this.d, this.repo, {super.key});
  final Detail d;
  final Repository repo;

  @override
  Widget build(BuildContext context) => _tab(context, [
        TermSection('checkpoints', children: [KV('確認ポイント', d.checkpoints)]),
        TermSection('logs', note: '関連度順', children: [
          for (final l in d.logs)
            if (repo.logs[l.id] case final s?)
              RuleCard(title: s.platform, trailing: 'r${l.rank}', subtitle: '${l.match} · ${l.via.take(3).join(', ')}',
                  onTap: () => push(context, LogDetailScreen(s, repo))),
        ]),
      ]);
}

class SourcesTab extends StatelessWidget {
  const SourcesTab(this.d, this.repo, {super.key});
  final Detail d;
  final Repository repo;

  @override
  Widget build(BuildContext context) => _tab(context, [
        TermSection('certainty', children: [KV('確度', d.certainty), KV('確認日', d.verified, mono: true), KV('未確認事項', d.notes),
          KV('未整備', d.gaps.join('\n'))]),
        TermSection('evidence', note: '根拠の確認内容', children: [
          for (final e in d.evidence)
            RuleCard(
              title: [e.kind, if (e.technique.isNotEmpty) e.technique].join(' · '),
              subtitle: [e.summary, if (e.examples.isNotEmpty) '例: ${e.examples.join(', ')}'].join('\n'),
              trailing: repo.sources[e.source]?.publisher ?? '',
              onTap: repo.sources[e.source] == null ? null : () => openLink(context, repo.sources[e.source]!.url),
            ),
        ]),
        TermSection('sources', children: [for (final id in d.sources) SourceRow(id, repo)]),
      ]);
}
