import 'package:flutter/material.dart';

import '../data/filters.dart';
import '../data/models.dart';
import '../data/repository.dart';
import 'filter_panel.dart';
import 'port_detail_screen.dart';
import 'theme.dart';
import 'widgets.dart';

class SearchScreen extends StatefulWidget {
  const SearchScreen({super.key, required this.repo});
  final Repository repo;

  @override
  State<SearchScreen> createState() => _SearchScreenState();
}

class _SearchScreenState extends State<SearchScreen> {
  final _controller = TextEditingController();
  String _query = '';
  SearchFilter _filter = const SearchFilter();
  bool _showFilter = false;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final results = widget.repo.search(_query, _filter);
    final n = _filter.activeCount;
    return CustomScrollView(slivers: [
      SliverToBoxAdapter(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(14, 10, 14, 6),
          child: TextField(
            key: const Key('search-field'),
            controller: _controller,
            maxLength: 100,
            style: Term.monoStyle(size: 14, color: Term.bright),
            textInputAction: TextInputAction.search,
            decoration: InputDecoration(
              counterText: '',
              prefixIcon: Padding(padding: const EdgeInsets.all(12), child: Text('>', style: Term.monoStyle(size: 14, color: Term.green, weight: FontWeight.w700))),
              hintText: '445/tcp, rdp, T1110, 4769, impacket',
              hintStyle: Term.monoStyle(color: Term.dim),
              suffixIcon: _query.isEmpty ? null : IconButton(tooltip: 'クリア', icon: const Icon(Icons.close, size: 18),
                  onPressed: () => setState(() { _controller.clear(); _query = ''; })),
            ),
            onChanged: (v) => setState(() => _query = v),
          ),
        ),
      ),
      SliverToBoxAdapter(
        child: Container(
          margin: const EdgeInsets.symmetric(horizontal: 14),
          decoration: BoxDecoration(color: Term.panel, border: Border.all(color: Term.line), borderRadius: BorderRadius.circular(6)),
          child: Column(children: [
            InkWell(
              key: const Key('filter-toggle'),
              onTap: () => setState(() => _showFilter = !_showFilter),
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 12),
                child: Row(children: [
                  Text('${_showFilter ? '▼' : '▶'} 詳細検索設定', style: Term.monoStyle(color: Term.amber, weight: FontWeight.w700)),
                  if (n > 0) Text(' ($n)', key: const Key('filter-count'), style: Term.monoStyle(color: Term.teal)),
                  const Spacer(),
                  if (n > 0 || _filter.sortBy != SortBy.relevance)
                    InkWell(onTap: () => setState(() => _filter = const SearchFilter()),
                        child: Text('reset', style: Term.monoStyle(size: 11, color: Term.dim))),
                ]),
              ),
            ),
            if (_showFilter)
              Padding(
                padding: const EdgeInsets.fromLTRB(10, 0, 10, 10),
                child: FilterPanel(repo: widget.repo, filter: _filter, onChanged: (f) => setState(() => _filter = f)),
              ),
          ]),
        ),
      ),
      SliverToBoxAdapter(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(14, 10, 14, 4),
          child: Text('${results.length} hits · sort: ${_filter.sortBy.name}', style: Term.monoStyle(size: 11, color: Term.dim)),
        ),
      ),
      if (results.isEmpty)
        SliverToBoxAdapter(child: Padding(padding: const EdgeInsets.all(24), child: Text('該当するポートはありません', style: Term.monoStyle(color: Term.dim))))
      else
        SliverList.builder(itemCount: results.length, itemBuilder: (c, i) => PortRow(results[i], repo: widget.repo)),
      SliverToBoxAdapter(child: SizedBox(height: 24 + MediaQuery.paddingOf(context).bottom)),
    ]);
  }
}

class PortRow extends StatelessWidget {
  const PortRow(this.e, {super.key, required this.repo, this.note});
  final PortEntry e;
  final Repository repo;
  final String? note;

  @override
  Widget build(BuildContext context) {
    final d = e.detail;
    final meta = note ?? (d == null
        ? 'iana · ${e.iana}'
        : [d.techniques.take(3).join(' '), d.tools.map((t) => repo.tools[t]?.name ?? t).take(2).join(', ')].where((s) => s.isNotEmpty).join(' · '));
    return InkWell(
      onTap: () => push(context, PortDetailScreen(entry: e, repo: repo)),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 9),
        decoration: const BoxDecoration(border: Border(top: BorderSide(color: Color(0xFF161B22)))),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [
            SizedBox(width: 92, child: Text(e.label, style: Term.monoStyle(size: 13, color: d == null ? Term.dim : Term.teal, weight: FontWeight.w700))),
            Expanded(child: Text(e.service, overflow: TextOverflow.ellipsis, style: Term.monoStyle(size: 13, color: Term.bright))),
            if (d != null) RiskTag(d.risk),
          ]),
          Padding(
            padding: const EdgeInsets.only(left: 92, top: 2),
            child: Text(meta, maxLines: 2, overflow: TextOverflow.ellipsis, style: Term.monoStyle(size: 11, color: Term.dim)),
          ),
        ]),
      ),
    );
  }
}
