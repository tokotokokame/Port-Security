import 'package:flutter/material.dart';

import '../data/repository.dart';
import 'widgets.dart';

class SearchScreen extends StatefulWidget {
  const SearchScreen({super.key, required this.repository});
  final PortRepository repository;

  @override
  State<SearchScreen> createState() => _SearchScreenState();
}

class _SearchScreenState extends State<SearchScreen> {
  final _controller = TextEditingController();
  String _query = '';
  static const _examples = ['3389', '445/tcp', 'udp 53', 'T1110', '4625', 'Kerberoasting', 'FortiGate'];

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _set(String q) {
    _controller.value = TextEditingValue(text: q, selection: TextSelection.collapsed(offset: q.length));
    setState(() => _query = q);
  }

  @override
  Widget build(BuildContext context) {
    final results = widget.repository.search(_query);
    return Column(children: [
      Padding(
        padding: const EdgeInsets.fromLTRB(12, 12, 12, 4),
        child: TextField(
          key: const Key('search-field'),
          controller: _controller,
          maxLength: 100,
          textInputAction: TextInputAction.search,
          decoration: InputDecoration(
            hintText: 'ポート番号・サービス名・攻撃手法・MITRE ID・イベントID',
            prefixIcon: const Icon(Icons.search),
            counterText: '',
            border: const OutlineInputBorder(),
            suffixIcon: _query.isEmpty
                ? null
                : IconButton(tooltip: 'クリア', icon: const Icon(Icons.clear), onPressed: () => _set('')),
          ),
          onChanged: (v) => setState(() => _query = v),
        ),
      ),
      SizedBox(
        height: 44,
        child: ListView(
          scrollDirection: Axis.horizontal,
          padding: const EdgeInsets.symmetric(horizontal: 8),
          children: [
            for (final e in _examples)
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 4),
                child: ActionChip(label: Text(e), onPressed: () => _set(e)),
              ),
          ],
        ),
      ),
      Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
        child: Align(
          alignment: Alignment.centerLeft,
          child: Text('${results.length} 件', style: Theme.of(context).textTheme.labelMedium),
        ),
      ),
      Expanded(
        child: results.isEmpty
            ? const Center(child: Text('該当するポートはありません'))
            : ListView.separated(
                itemCount: results.length,
                separatorBuilder: (_, _) => const Divider(height: 1),
                itemBuilder: (_, i) => PortTile(results[i]),
              ),
      ),
    ]);
  }
}
