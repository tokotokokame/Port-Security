import 'dart:convert';

import 'package:flutter/services.dart';

import 'models.dart';
import 'text.dart';

const kDataAsset = 'assets/data/port_index.json';
const _transports = {'tcp', 'udp', 'sctp'};

/// A group of ports sharing one attack pattern or log source.
class Group {
  Group(this.id, this.title, this.subtitle);
  final String id, title, subtitle;
  final List<PortEntry> ports = [];
}

class PortRepository {
  PortRepository(List<PortEntry> ports)
      : ports = List<PortEntry>.unmodifiable(List<PortEntry>.of(ports)..sort(_byPort));

  final List<PortEntry> ports;

  static int _byPort(PortEntry a, PortEntry b) =>
      a.number != b.number ? a.number.compareTo(b.number) : a.transport.compareTo(b.transport);

  /// Throws [FormatException] if the asset is not a JSON array of objects.
  factory PortRepository.fromJsonString(String raw) {
    final decoded = jsonDecode(raw);
    if (decoded is! List) throw const FormatException('port_index.json must be a JSON array');
    return PortRepository(decoded.whereType<Map<String, dynamic>>().map(PortEntry.fromJson).toList());
  }

  static Future<PortRepository> load([AssetBundle? bundle]) async =>
      PortRepository.fromJsonString(await (bundle ?? rootBundle).loadString(kDataAsset));

  late final Set<int> _numbers = {for (final p in ports) p.number};

  /// Tokens: "tcp"/"udp" filter the transport, a number that is a known port
  /// matches the port number exactly, everything else is a substring match.
  /// "445/tcp", "TCP 445" and "４４５" are all accepted.
  List<PortEntry> search(String input) {
    final tokens = normalizeText(input).split(RegExp(r'[\s/:]+')).where((t) => t.isNotEmpty).toList();
    if (tokens.isEmpty) return ports;
    final transports = tokens.where(_transports.contains).toSet();
    final terms = tokens.where((t) => !_transports.contains(t)).toList();
    bool matches(PortEntry p, String t) {
      final n = int.tryParse(t);
      return n != null && _numbers.contains(n) ? p.number == n : p.searchText.contains(t);
    }

    // number > service/formal name > port-specific text > shared attack/log text
    int score(PortEntry p) => terms.fold(0, (s, t) {
          if (int.tryParse(t) == p.number) return s + 100;
          if (p.nameText.contains(t)) return s + 10;
          return s + (p.ownText.contains(t) ? 5 : 1);
        });

    final hits = ports
        .where((p) => transports.isEmpty || transports.contains(p.transport.toLowerCase()))
        .where((p) => terms.every((t) => matches(p, t)))
        .toList();
    final scores = {for (final p in hits) p: score(p)};
    hits.sort((a, b) {
      final d = scores[b]!.compareTo(scores[a]!);
      return d != 0 ? d : _byPort(a, b);
    });
    return hits;
  }

  late final List<Group> attackGroups = _group(
      (p) => [for (final a in p.attacks) (a.id, a.name, a.features)]);

  late final List<Group> logGroups = _group(
      (p) => [for (final l in p.logs) (l.id, l.platform, l.analytics)]);

  List<Group> _group(List<(String, String, String)> Function(PortEntry) keys) {
    final map = <String, Group>{};
    for (final p in ports) {
      for (final (id, title, sub) in keys(p)) {
        map.putIfAbsent(id, () => Group(id, title, sub)).ports.add(p);
      }
    }
    return map.values.toList()..sort((a, b) => b.ports.length.compareTo(a.ports.length));
  }
}
