import 'package:flutter/material.dart';

import '../data/models.dart';
import '../data/repository.dart';
import 'detail_tabs.dart';
import 'theme.dart';
import 'widgets.dart';

class PortDetailScreen extends StatelessWidget {
  const PortDetailScreen({super.key, required this.entry, required this.repo});
  final PortEntry entry;
  final Repository repo;

  @override
  Widget build(BuildContext context) {
    final d = entry.detail;
    final tabs = d == null
        ? const ['概要']
        : const ['概要', '攻撃', 'tools', 'att&ck', 'logs', 'src'];
    return DefaultTabController(
      length: tabs.length,
      child: Scaffold(
        appBar: AppBar(
          title: Text.rich(TextSpan(children: [
            TextSpan(text: '~/ports/', style: Term.monoStyle(size: 13, color: Term.dim)),
            TextSpan(text: '${entry.number}-${entry.transport.toLowerCase()}', style: Term.monoStyle(size: 13, color: Term.teal, weight: FontWeight.w700)),
          ])),
        ),
        body: NestedScrollView(
          headerSliverBuilder: (c, _) => [
            SliverToBoxAdapter(child: _Header(entry)),
            SliverToBoxAdapter(child: TabBar(isScrollable: true, tabs: [for (final t in tabs) Tab(text: t, height: 40)])),
          ],
          body: TabBarView(children: d == null
              ? [IanaOnlyTab(entry)]
              : [
                  OverviewTab(entry, repo),
                  AttackTab(d, repo),
                  ToolsTab(d, repo),
                  AttackMatrixTab(d, repo),
                  LogsTab(d, repo),
                  SourcesTab(d, repo),
                ]),
        ),
      ),
    );
  }
}

class _Header extends StatelessWidget {
  const _Header(this.e);
  final PortEntry e;

  @override
  Widget build(BuildContext context) {
    final d = e.detail;
    return Padding(
      padding: const EdgeInsets.fromLTRB(14, 6, 14, 10),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Row(crossAxisAlignment: CrossAxisAlignment.baseline, textBaseline: TextBaseline.alphabetic, children: [
          Text(e.label, style: Term.monoStyle(size: 26, color: Term.bright, weight: FontWeight.w700)),
          const SizedBox(width: 10),
          Flexible(child: Text(e.service, overflow: TextOverflow.ellipsis, style: Term.monoStyle(size: 13, color: Term.dim))),
        ]),
        if (e.title.isNotEmpty) Text(e.title, style: const TextStyle(fontSize: 14, color: Term.text)),
        const SizedBox(height: 6),
        Wrap(spacing: 6, runSpacing: 4, children: [
          if (d != null) RiskTag(d.risk),
          if (d != null) Tag(d.certainty == '確認済み' ? 'verified' : 'partial', color: d.certainty == '確認済み' ? Term.green : Term.amber),
          const Tag('IANA ✓'),
          if (d == null) const Tag('詳細未整備'),
          if (e.unauthorized.isNotEmpty) const Tag('非公認利用の報告あり', color: Term.orange),
          Tag(e.portClass),
        ]),
      ]),
    );
  }
}
