import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../data/filters.dart';
import '../data/repository.dart';
import 'theme.dart';

/// "詳細検索設定": 基本 / 脅威 / 調査 / 並び替え.
class FilterPanel extends StatelessWidget {
  const FilterPanel({super.key, required this.repo, required this.filter, required this.onChanged});
  final Repository repo;
  final SearchFilter filter;
  final ValueChanged<SearchFilter> onChanged;

  @override
  Widget build(BuildContext context) {
    final f = filter;
    void set(SearchFilter n) => onChanged(n);
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      _group('基本'),
      _Row('transport', _Seg(['any', 'tcp', 'udp'], f.transport?.toLowerCase() ?? 'any',
          (v) => set(f.copyWith(transport: v == 'any' ? null : v.toUpperCase())))),
      _Row('class', _Seg(['all', 'well-known', 'registered', 'dynamic'], const ['all', 'well-known', 'registered', 'dynamic'][f.portClass.index],
          (v) => set(f.copyWith(portClass: PortClass.values[const ['all', 'well-known', 'registered', 'dynamic'].indexOf(v)])))),
      _Row('range', Row(children: [
        _NumField(key: const Key('min-port'), value: f.minPort, hint: '0', onChanged: (v) => set(f.copyWith(minPort: v))),
        Padding(padding: const EdgeInsets.symmetric(horizontal: 6), child: Text('–', style: Term.monoStyle(color: Term.dim))),
        _NumField(key: const Key('max-port'), value: f.maxPort, hint: '65535', onChanged: (v) => set(f.copyWith(maxPort: v))),
      ])),
      _Row('detail', _Seg(['all', '詳細ありのみ'], f.detailOnly ? '詳細ありのみ' : 'all', (v) => set(f.copyWith(detailOnly: v != 'all')))),
      _group('脅威'),
      _Row('risk ≥', _Seg(['any', 'Low', 'Medium', 'High', 'Critical'], f.minRisk ?? 'any', (v) => set(f.copyWith(minRisk: v == 'any' ? null : v)))),
      _Row('attack', _Picker('攻撃手法', f.attack, {for (final a in repo.attacks.values) a.id: a.name}, (v) => set(f.copyWith(attack: v)))),
      _Row('tool', _Picker('攻撃ツール', f.tool, {for (final t in repo.tools.values) t.id: t.name}, (v) => set(f.copyWith(tool: v)))),
      _Row('tactic', _Picker('MITRE 戦術', f.tactic, {for (final t in repo.tactics) t: t}, (v) => set(f.copyWith(tactic: v)))),
      _group('調査'),
      _Row('log', _Picker('ログ基盤', f.log, {for (final l in repo.logs.values) l.id: l.platform}, (v) => set(f.copyWith(log: v)))),
      _Row('certainty', _Seg(['all', '確認済み'], f.verifiedOnly ? '確認済み' : 'all', (v) => set(f.copyWith(verifiedOnly: v != 'all')))),
      _group('並び替え'),
      _Row('sort', _Seg(['relevance', 'port', 'risk'], f.sortBy.name, (v) => set(f.copyWith(sortBy: SortBy.values.byName(v))))),
    ]);
  }

  Widget _group(String t) => Padding(
      padding: const EdgeInsets.only(top: 8, bottom: 2), child: Text('-- $t', style: Term.monoStyle(size: 11, color: Term.dim)));
}

class _Row extends StatelessWidget {
  const _Row(this.label, this.child);
  final String label;
  final Widget child;

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 3),
        child: Row(crossAxisAlignment: CrossAxisAlignment.center, children: [
          SizedBox(width: 78, child: Text(label, style: Term.monoStyle(color: Term.dim))),
          Expanded(child: child),
        ]),
      );
}

class _Seg extends StatelessWidget {
  const _Seg(this.options, this.selected, this.onTap);
  final List<String> options;
  final String selected;
  final ValueChanged<String> onTap;

  @override
  Widget build(BuildContext context) => Wrap(spacing: 4, runSpacing: 4, children: [
        for (final o in options)
          Semantics(
            selected: o == selected,
            button: true,
            child: InkWell(
              onTap: () => onTap(o),
              child: Container(
                constraints: const BoxConstraints(minHeight: 34),
                alignment: Alignment.center,
                padding: const EdgeInsets.symmetric(horizontal: 9),
                decoration: BoxDecoration(color: o == selected ? Term.teal : null,
                    border: Border.all(color: o == selected ? Term.teal : Term.line), borderRadius: BorderRadius.circular(4)),
                child: Text(o, style: Term.monoStyle(color: o == selected ? Term.bg : Term.dim, weight: o == selected ? FontWeight.w700 : FontWeight.w400)),
              ),
            ),
          ),
      ]);
}

class _Picker extends StatelessWidget {
  const _Picker(this.title, this.value, this.options, this.onChanged);
  final String title;
  final String? value;
  final Map<String, String> options;
  final ValueChanged<String?> onChanged;

  Future<void> _open(BuildContext context) async {
    final picked = await showModalBottomSheet<String>(
      context: context, useSafeArea: true, isScrollControlled: true, backgroundColor: Term.panel,
      builder: (c) => ConstrainedBox(
        constraints: BoxConstraints(maxHeight: MediaQuery.sizeOf(c).height * 0.7),
        child: ListView(shrinkWrap: true, padding: EdgeInsets.only(bottom: 16 + MediaQuery.paddingOf(c).bottom), children: [
          ListTile(title: Text(title, style: Term.monoStyle(size: 13, color: Term.amber, weight: FontWeight.w700))),
          ListTile(title: Text('指定なし', style: Term.monoStyle(color: Term.dim)), onTap: () => Navigator.pop(c, '')),
          for (final e in options.entries)
            ListTile(
              selected: e.key == value, selectedColor: Term.teal,
              title: Text(e.value, style: const TextStyle(fontSize: 13)),
              subtitle: e.key == e.value ? null : Text(e.key, style: Term.monoStyle(size: 11, color: Term.dim)),
              onTap: () => Navigator.pop(c, e.key)),
        ]),
      ),
    );
    if (picked != null) onChanged(picked.isEmpty ? null : picked);
  }

  @override
  Widget build(BuildContext context) => InkWell(
        onTap: () => _open(context),
        child: Container(
          constraints: const BoxConstraints(minHeight: 34),
          padding: const EdgeInsets.symmetric(horizontal: 9),
          decoration: BoxDecoration(border: Border.all(color: value == null ? Term.line : Term.teal), borderRadius: BorderRadius.circular(4)),
          child: Row(children: [
            Expanded(child: Text(value == null ? 'any' : (options[value] ?? value!), overflow: TextOverflow.ellipsis,
                style: Term.monoStyle(color: value == null ? Term.dim : Term.bright))),
            const Icon(Icons.arrow_drop_down, size: 18, color: Term.dim),
          ]),
        ),
      );
}

class _NumField extends StatefulWidget {
  const _NumField({super.key, required this.value, required this.hint, required this.onChanged});
  final int? value;
  final String hint;
  final ValueChanged<int?> onChanged;

  @override
  State<_NumField> createState() => _NumFieldState();
}

class _NumFieldState extends State<_NumField> {
  late final _c = TextEditingController(text: widget.value?.toString() ?? '');

  @override
  void didUpdateWidget(_NumField old) {
    super.didUpdateWidget(old);
    if (widget.value == null && _c.text.isNotEmpty) _c.clear();
  }

  @override
  void dispose() {
    _c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => SizedBox(
        width: 86,
        child: TextField(
          controller: _c, keyboardType: TextInputType.number, maxLength: 5, style: Term.monoStyle(color: Term.bright),
          inputFormatters: [FilteringTextInputFormatter.digitsOnly],
          decoration: InputDecoration(hintText: widget.hint, counterText: '', hintStyle: Term.monoStyle(color: Term.dim)),
          onChanged: (t) {
            final n = int.tryParse(t);
            widget.onChanged(n == null ? null : n.clamp(0, 65535));
          },
        ),
      );
}
