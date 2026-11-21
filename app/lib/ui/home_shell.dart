import 'package:flutter/material.dart';

import '../data/repository.dart';
import 'about_screen.dart';
import 'kb_screens.dart';
import 'search_screen.dart';
import 'theme.dart';
import 'widgets.dart';

class HomeShell extends StatefulWidget {
  const HomeShell({super.key, required this.repo});
  final Repository repo;

  @override
  State<HomeShell> createState() => _HomeShellState();
}

class _HomeShellState extends State<HomeShell> {
  int _tab = 0;
  static const _paths = ['~/ports', '~/attacks', '~/tools', '~/logs'];

  @override
  Widget build(BuildContext context) {
    final r = widget.repo;
    final detailed = r.detailed.length;
    return Scaffold(
      appBar: AppBar(
        toolbarHeight: 60,
        title: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('port-security', style: Term.monoStyle(size: 14, color: Term.green, weight: FontWeight.w700)),
          Text('${_paths[_tab]} · 詳細 $detailed / IANA ${r.entries.length} · offline', style: Term.monoStyle(size: 11, color: Term.dim)),
        ]),
        actions: [
          IconButton(tooltip: 'このアプリについて', icon: const Icon(Icons.info_outline, color: Term.dim),
              onPressed: () => push(context, AboutScreen(repo: r))),
        ],
      ),
      body: IndexedStack(index: _tab, children: [
        SearchScreen(repo: r),
        KbList(items: [
          for (final a in r.attacks.values)
            (a.name, a.category, a.id, AttackDetailScreen(a, r)),
        ]),
        KbList(items: [
          for (final t in r.tools.values)
            (t.name, t.sid ?? '', '${t.category} · ${t.ports.take(4).join(' ')}', ToolDetailScreen(t, r)),
        ]),
        KbList(items: [
          for (final l in r.logs.values)
            (l.platform, l.certainty, l.id, LogDetailScreen(l, r)),
        ]),
      ]),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _tab,
        onDestinationSelected: (i) => setState(() => _tab = i),
        destinations: const [
          NavigationDestination(icon: Icon(Icons.lan_outlined), label: 'ports'),
          NavigationDestination(icon: Icon(Icons.gpp_maybe_outlined), label: 'attacks'),
          NavigationDestination(icon: Icon(Icons.construction_outlined), label: 'tools'),
          NavigationDestination(icon: Icon(Icons.receipt_long_outlined), label: 'logs'),
        ],
      ),
    );
  }
}
