import 'dart:convert';

import 'package:flutter/services.dart';

import 'filters.dart';
import 'json.dart';
import 'models.dart';

const kAssets = ('assets/data/ports.json', 'assets/data/kb.json', 'assets/data/iana.json');
const _transports = {'tcp', 'udp', 'sctp', 'dccp'};

class Repository {
  Repository({required List<Json> ports, required Json kb, required List<List<dynamic>> iana}) {
    Map<String, T> table<T>(String key, T Function(String, Json) f) =>
        {for (final e in obj(kb[key]).entries) if (e.value is Json) e.key: f(e.key, e.value as Json)};
    attacks = table('attacks', Attack.new);
    techniques = table('techniques', Technique.new);
    dets = table('dets', Det.new);
    tools = table('tools', Tool.new);
    logs = table('logs', LogSource.new);
    sources = table('sources', Source.new);
    meta = obj(kb['meta']);
    final ianaByKey = {for (final r in iana) if (r.length == 5 && r[0] is int) '${r[0]}/${str(r[1])}': r};
    final seen = <String>{};
    final list = <PortEntry>[];
    for (final p in ports) {
      final key = '${intOr(p['n'])}/${str(p['t'])}';
      final i = ianaByKey[key];
      seen.add(key);
      list.add(PortEntry(number: intOr(p['n']), transport: str(p['t']), service: str(p['service']),
          iana: str(p['iana']), unauthorized: i == null ? '' : str(i[4]), detail: Detail(p)));
    }
    for (final r in ianaByKey.entries) {
      if (seen.contains(r.key)) continue;
      list.add(PortEntry(number: r.value[0] as int, transport: str(r.value[1]), service: str(r.value[2]),
          iana: str(r.value[3]), unauthorized: str(r.value[4])));
    }
    list.sort((a, b) => a.number != b.number ? a.number.compareTo(b.number) : a.transport.compareTo(b.transport));
    entries = List.unmodifiable(list);
    _numbers = {for (final e in entries) e.number};
  }

  late final Map<String, Attack> attacks;
  late final Map<String, Technique> techniques;
  late final Map<String, Det> dets;
  late final Map<String, Tool> tools;
  late final Map<String, LogSource> logs;
  late final Map<String, Source> sources;
  late final Json meta;
  late final List<PortEntry> entries;
  late final Set<int> _numbers;
  late final List<PortEntry> detailed = entries.where((e) => e.detail != null).toList();
  late final List<String> tactics = {for (final t in techniques.values) ...t.tactics}.toList()..sort();

  /// Throws [FormatException] when an asset has the wrong top-level shape.
  factory Repository.fromStrings(String ports, String kb, String iana) {
    final p = jsonDecode(ports), k = jsonDecode(kb), i = jsonDecode(iana);
    if (p is! List || k is! Json || i is! List) throw const FormatException('unexpected asset shape');
    return Repository(ports: p.whereType<Json>().toList(), kb: k, iana: i.whereType<List<dynamic>>().toList());
  }

  static Future<Repository> load([AssetBundle? bundle]) async {
    final b = bundle ?? rootBundle;
    return Repository.fromStrings(await b.loadString(kAssets.$1), await b.loadString(kAssets.$2), await b.loadString(kAssets.$3));
  }

  final Map<PortEntry, String> _text = {};

  /// Port text plus the names of linked attacks, tools, techniques and logs.
  String searchText(PortEntry e) => _text.putIfAbsent(e, () {
        final d = e.detail;
        if (d == null) return e.ownText;
        return normalizeText([
          e.ownText,
          for (final a in d.attacks) ...[a, attacks[a]?.name ?? '', attacks[a]?.detection ?? ''],
          for (final t in d.tools) ...[t, tools[t]?.name ?? ''],
          for (final t in d.techniques) techniques[t]?.name ?? '',
          for (final l in d.logs) ...[l.id, logs[l.id]?.platform ?? ''],
        ].join('\n'));
      });

  /// Tokens: tcp/udp filter the transport; a number that is a known port
  /// matches exactly; anything else is a substring. "445/tcp" and "４４５" work.
  List<PortEntry> search(String input, [SearchFilter filter = const SearchFilter()]) {
    final tokens = normalizeText(input).split(RegExp(r'[\s/:,]+')).where((t) => t.isNotEmpty).toList();
    final transports = tokens.where(_transports.contains).toSet();
    final terms = tokens.where((t) => !_transports.contains(t)).toList();
    bool matches(PortEntry e, String t) {
      final n = int.tryParse(t);
      return n != null && _numbers.contains(n) ? e.number == n : searchText(e).contains(t);
    }

    int score(PortEntry e) => terms.fold(e.detail == null ? 0 : 1, (s, t) {
          if (int.tryParse(t) == e.number) return s + 100;
          if (e.nameText.contains(t)) return s + 10;
          return s + (e.ownText.contains(t) ? 5 : 1);
        });
    final hits = entries
        .where((e) => transports.isEmpty || transports.contains(e.transport.toLowerCase()))
        .where((e) => terms.every((t) => matches(e, t)))
        .where((e) => filter.accepts(e, this))
        .toList();
    return filter.sort(hits, terms.isEmpty ? null : {for (final e in hits) e: score(e)});
  }

  List<PortEntry> portsWhere(bool Function(Detail d) test) => detailed.where((e) => test(e.detail!)).toList();
}
