import 'package:flutter/material.dart';

import '../data/repository.dart';
import 'about_screen.dart';
import 'group_screens.dart';
import 'search_screen.dart';

class HomeShell extends StatefulWidget {
  const HomeShell({super.key, required this.repository});
  final PortRepository repository;

  @override
  State<HomeShell> createState() => _HomeShellState();
}

class _HomeShellState extends State<HomeShell> {
  int _tab = 0;
  static const _titles = ['ポート検索', '攻撃手法から探す', 'ログ調査から探す'];

  @override
  Widget build(BuildContext context) {
    final repo = widget.repository;
    return Scaffold(
      appBar: AppBar(
        title: Text(_titles[_tab]),
        actions: [
          IconButton(
            tooltip: 'このアプリについて',
            icon: const Icon(Icons.info_outline),
            onPressed: () => Navigator.of(context).push(
              MaterialPageRoute<void>(builder: (_) => AboutScreen(repository: repo)),
            ),
          ),
        ],
      ),
      body: IndexedStack(
        index: _tab,
        children: [
          SearchScreen(repository: repo),
          GroupListScreen(groups: repo.attackGroups, kind: GroupKind.attack),
          GroupListScreen(groups: repo.logGroups, kind: GroupKind.log),
        ],
      ),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _tab,
        onDestinationSelected: (i) => setState(() => _tab = i),
        destinations: const [
          NavigationDestination(icon: Icon(Icons.search), label: 'ポート'),
          NavigationDestination(icon: Icon(Icons.gpp_maybe_outlined), label: '攻撃手法'),
          NavigationDestination(icon: Icon(Icons.receipt_long_outlined), label: 'ログ調査'),
        ],
      ),
    );
  }
}
