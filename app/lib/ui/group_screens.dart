import 'package:flutter/material.dart';

import '../data/models.dart';
import '../data/repository.dart';
import 'widgets.dart';

enum GroupKind { attack, log }

class GroupListScreen extends StatelessWidget {
  const GroupListScreen({super.key, required this.groups, required this.kind});
  final List<Group> groups;
  final GroupKind kind;

  @override
  Widget build(BuildContext context) {
    if (groups.isEmpty) return const Center(child: Text('データがありません'));
    return ListView.separated(
      itemCount: groups.length,
      separatorBuilder: (_, _) => const Divider(height: 1),
      itemBuilder: (context, i) {
        final g = groups[i];
        return ListTile(
          title: Text(g.title),
          subtitle: Text('${g.id}\n${g.subtitle}', maxLines: 3, overflow: TextOverflow.ellipsis),
          isThreeLine: true,
          trailing: Pill('${g.ports.length}ポート'),
          onTap: () => Navigator.of(context).push(MaterialPageRoute<void>(
            builder: (_) => GroupDetailScreen(group: g, kind: kind),
          )),
        );
      },
    );
  }
}

class GroupDetailScreen extends StatelessWidget {
  const GroupDetailScreen({super.key, required this.group, required this.kind});
  final Group group;
  final GroupKind kind;

  LogRef? _log(PortEntry p) => p.logs.where((l) => l.id == group.id).firstOrNull;
  AttackRef? _attack(PortEntry p) => p.attacks.where((a) => a.id == group.id).firstOrNull;

  @override
  Widget build(BuildContext context) {
    final ports = [...group.ports];
    if (kind == GroupKind.log) {
      ports.sort((a, b) => (_log(a)?.rank ?? 9).compareTo(_log(b)?.rank ?? 9));
    }
    final first = ports.isEmpty ? null : ports.first;
    final atk = first == null ? null : _attack(first);
    final log = first == null ? null : _log(first);
    return Scaffold(
      appBar: AppBar(title: Text(group.title)),
      body: ListView(padding: const EdgeInsets.only(bottom: 24), children: [
        if (atk != null)
          Section(atk.id, icon: Icons.gpp_maybe_outlined, children: [
            Field('特徴', atk.features),
            Field('検知方法', atk.detection),
            Field('対策', atk.defenses),
          ]),
        if (log != null)
          Section(log.id, icon: Icons.receipt_long_outlined, children: [
            Field('検知ロジック', log.analytics),
            Field('調査手順', log.procedure),
            Field('確度', log.certainty),
          ]),
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 4),
          child: Text('対象ポート（${ports.length}）', style: Theme.of(context).textTheme.titleMedium),
        ),
        for (final p in ports)
          PortTile(p, trailingNote: kind == GroupKind.log ? '関連度: ${_log(p)?.match ?? '-'}' : null),
      ]),
    );
  }
}
