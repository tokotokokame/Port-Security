import 'package:flutter/material.dart';

import '../data/models.dart';
import '../data/repository.dart';
import 'search_screen.dart';
import 'theme.dart';
import 'widgets.dart';

/// Technique with its detection strategies and the log sources ATT&CK names.
class TechniqueCard extends StatelessWidget {
  const TechniqueCard(this.t, this.repo, {super.key, this.basis});
  final Technique t;
  final Repository repo;
  final Basis? basis;

  @override
  Widget build(BuildContext context) => Theme(
        data: Theme.of(context).copyWith(dividerColor: Colors.transparent),
        child: ExpansionTile(
          tilePadding: EdgeInsets.zero,
          childrenPadding: const EdgeInsets.only(left: 10, bottom: 8),
          expandedCrossAxisAlignment: CrossAxisAlignment.start,
          title: Text('${t.id}  ${t.name}', style: Term.monoStyle(color: Term.bright, weight: FontWeight.w700)),
          subtitle: Text([t.tactics.join(' / '), if (basis != null) '関連: ${basis!.label}'].join('\n'),
              style: Term.monoStyle(size: 11, color: Term.dim)),
          children: [
            if (basis != null)
              KV('関連の根拠', [basis!.label, if (basis!.via.isNotEmpty) '経路: ${basis!.via.join(', ')}', if (basis!.note.isNotEmpty) basis!.note].join('\n')),
            for (final did in t.dets)
              if (repo.dets[did] case final det?) ...[
                Text('$did  ${det.name}', style: Term.monoStyle(size: 12, color: Term.teal)),
                for (final a in det.analytics) ...[
                  Text('  ${a.id} [${a.platforms.join(', ')}]', style: Term.monoStyle(size: 11, color: Term.amber)),
                  for (final l in a.logs) Bullet(l, color: Term.text),
                ],
                const SizedBox(height: 6),
              ],
            if (t.dets.isEmpty) Text('検知戦略の登録なし', style: Term.monoStyle(size: 11, color: Term.dim)),
            TextButton.icon(onPressed: () => openLink(context, t.url), icon: const Icon(Icons.open_in_new, size: 16),
                label: Text('attack.mitre.org', style: Term.monoStyle(size: 11, color: Term.teal))),
          ],
        ),
      );
}

class SourceRow extends StatelessWidget {
  const SourceRow(this.id, this.repo, {super.key});
  final String id;
  final Repository repo;

  @override
  Widget build(BuildContext context) {
    final s = repo.sources[id];
    if (s == null) return const SizedBox.shrink();
    final state = s.certainty.isNotEmpty ? s.certainty : (s.verified ? '確認済み' : '未確認');
    return RuleCard(title: s.title, trailing: state, subtitle: [s.url, if (s.checked.isNotEmpty) '確認日 ${s.checked}'].join('\n'),
        onTap: () => openLink(context, s.url));
  }
}

class _Scaffold extends StatelessWidget {
  const _Scaffold(this.path, this.children);
  final String path;
  final List<Widget> children;

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(title: Text(path, overflow: TextOverflow.ellipsis)),
        body: ListView(padding: listPadding(context), children: children),
      );
}

List<Widget> _ports(Repository repo, List<PortEntry> ports, [String Function(PortEntry)? note]) => [
      Padding(padding: const EdgeInsets.fromLTRB(14, 12, 14, 4),
          child: Text('# ports  ${ports.length}', style: Term.monoStyle(size: 13, color: Term.amber, weight: FontWeight.w700))),
      for (final p in ports) PortRow(p, repo: repo, note: note?.call(p)),
    ];

class AttackDetailScreen extends StatelessWidget {
  const AttackDetailScreen(this.a, this.repo, {super.key});
  final Attack a;
  final Repository repo;

  @override
  Widget build(BuildContext context) => _Scaffold('~/attacks/${a.id}', [
        TermSection(a.name, note: a.category, children: [KV('概要', a.description), KV('特徴', a.features), KV('検知方法', a.detection), KV('対策', a.defenses)]),
        ReviewSection(certainty: a.certainty, verified: a.verified, notes: a.notes),
        TermSection('att&ck', children: [for (final id in a.techniques) if (repo.techniques[id] case final t?) TechniqueCard(t, repo)]),
        TermSection('tools', children: [
          for (final t in repo.tools.values.where((t) => t.attacks.contains(a.id)))
            RuleCard(title: t.name, trailing: t.category, onTap: () => push(context, ToolDetailScreen(t, repo))),
        ]),
        TermSection('logs', children: [
          for (final id in a.logs) if (repo.logs[id] case final l?) RuleCard(title: l.platform, onTap: () => push(context, LogDetailScreen(l, repo))),
        ]),
        TermSection('sources', children: [for (final id in a.sources) SourceRow(id, repo)]),
        ..._ports(repo, repo.portsWhere((d) => d.attacks.contains(a.id))),
      ]);
}

class ToolDetailScreen extends StatelessWidget {
  const ToolDetailScreen(this.t, this.repo, {super.key});
  final Tool t;
  final Repository repo;

  @override
  Widget build(BuildContext context) => _Scaffold('~/tools/${t.id}', [
        TermSection(t.name, note: [t.category, if (t.sid != null) t.sid!].join(' · '), children: [
          KV('概要', t.summary), KV('主なポート', t.ports.join('  '), mono: true),
        ]),
        ReviewSection(certainty: t.certainty, verified: t.verified, notes: t.notes),
        TermSection('artifacts', note: '検知の痕跡', children: [for (final a in t.artifacts) Bullet(a)]),
        TermSection('detection', children: [for (final x in t.detection) Bullet(x)]),
        TermSection('attacks', children: [
          for (final id in t.attacks) if (repo.attacks[id] case final a?) RuleCard(title: a.name, onTap: () => push(context, AttackDetailScreen(a, repo))),
        ]),
        TermSection('att&ck', note: '${t.techniques.length}', children: [
          for (final id in t.techniques) if (repo.techniques[id] case final x?) TechniqueCard(x, repo),
        ]),
        TermSection('logs', children: [
          for (final id in t.logs) if (repo.logs[id] case final l?) RuleCard(title: l.platform, onTap: () => push(context, LogDetailScreen(l, repo))),
        ]),
        TermSection('sources', children: [for (final id in t.sources) SourceRow(id, repo)]),
        ..._ports(repo, repo.portsWhere((d) => d.tools.contains(t.id))),
      ]);
}

class LogDetailScreen extends StatelessWidget {
  const LogDetailScreen(this.l, this.repo, {super.key});
  final LogSource l;
  final Repository repo;

  @override
  Widget build(BuildContext context) {
    LogRef? ref(PortEntry p) => p.detail!.logs.where((x) => x.id == l.id).firstOrNull;
    final ports = repo.portsWhere((d) => d.logs.any((x) => x.id == l.id))..sort((a, b) => (ref(a)?.rank ?? 9).compareTo(ref(b)?.rank ?? 9));
    return _Scaffold('~/logs/${l.id}', [
      TermSection(l.platform, children: [KV('検知ロジック', l.analytics), KV('調査手順', l.procedure)]),
      ReviewSection(certainty: l.certainty, verified: l.verified, notes: l.notes),
      TermSection('channels', children: [
        for (final (ch, code, desc) in l.channels) RuleCard(title: code == null ? ch : '$ch  $code', subtitle: desc),
      ]),
      TermSection('sources', children: [for (final id in l.refs) SourceRow(id, repo)]),
      ..._ports(repo, ports, (p) => '関連度: ${ref(p)?.match ?? '-'}'),
    ]);
  }
}

/// Tab bodies for the bottom navigation.
class KbList extends StatelessWidget {
  const KbList({super.key, required this.items});
  final List<(String, String, String, Widget)> items;

  @override
  Widget build(BuildContext context) => ListView(padding: listPadding(context).copyWith(left: 14, right: 14, top: 10), children: [
        for (final (title, trailing, sub, page) in items) RuleCard(title: title, trailing: trailing, subtitle: sub, onTap: () => push(context, page)),
      ]);
}
