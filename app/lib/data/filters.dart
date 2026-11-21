import 'models.dart';
import 'repository.dart';

enum PortClass { all, wellKnown, registered, dynamic }

enum SortBy { port, risk, relevance }

/// Immutable "詳細検索設定". Null fields mean "no constraint".
class SearchFilter {
  const SearchFilter({
    this.transport, this.portClass = PortClass.all, this.minPort, this.maxPort, this.detailOnly = false,
    this.minRisk, this.attack, this.tool, this.tactic, this.log, this.verifiedOnly = false, this.sortBy = SortBy.relevance,
  });

  final String? transport, minRisk, attack, tool, tactic, log;
  final PortClass portClass;
  final int? minPort, maxPort;
  final bool detailOnly, verifiedOnly;
  final SortBy sortBy;

  /// Number of active constraints (sort order is not counted).
  int get activeCount => [transport, minRisk, attack, tool, tactic, log, minPort, maxPort].where((v) => v != null).length +
      (portClass != PortClass.all ? 1 : 0) + (detailOnly ? 1 : 0) + (verifiedOnly ? 1 : 0);

  SearchFilter copyWith({
    Object? transport = _keep, PortClass? portClass, Object? minPort = _keep, Object? maxPort = _keep, bool? detailOnly,
    Object? minRisk = _keep, Object? attack = _keep, Object? tool = _keep, Object? tactic = _keep, Object? log = _keep,
    bool? verifiedOnly, SortBy? sortBy,
  }) {
    T? pick<T>(Object? v, T? old) => identical(v, _keep) ? old : v as T?;
    return SearchFilter(
      transport: pick(transport, this.transport), portClass: portClass ?? this.portClass,
      minPort: pick(minPort, this.minPort), maxPort: pick(maxPort, this.maxPort), detailOnly: detailOnly ?? this.detailOnly,
      minRisk: pick(minRisk, this.minRisk), attack: pick(attack, this.attack), tool: pick(tool, this.tool),
      tactic: pick(tactic, this.tactic), log: pick(log, this.log), verifiedOnly: verifiedOnly ?? this.verifiedOnly,
      sortBy: sortBy ?? this.sortBy,
    );
  }

  bool accepts(PortEntry e, Repository repo) {
    if (transport != null && e.transport != transport) return false;
    if (portClass != PortClass.all && e.portClass != _classLabel[portClass]) return false;
    if (minPort != null && e.number < minPort!) return false;
    if (maxPort != null && e.number > maxPort!) return false;
    final threat = minRisk != null || attack != null || tool != null || tactic != null || log != null || verifiedOnly;
    final d = e.detail;
    if (d == null) return !detailOnly && !threat;
    if (minRisk != null && (d.risk?.order ?? 0) < (riskOrder[minRisk] ?? 0)) return false;
    if (attack != null && !d.attacks.contains(attack)) return false;
    if (tool != null && !d.tools.contains(tool)) return false;
    if (log != null && !d.logs.any((l) => l.id == log)) return false;
    if (verifiedOnly && d.certainty != '確認済み') return false;
    if (tactic != null && !d.techniques.any((t) => repo.techniques[t]?.tactics.contains(tactic) ?? false)) return false;
    return true;
  }

  List<PortEntry> sort(List<PortEntry> hits, Map<PortEntry, int>? scores) {
    int byPort(PortEntry a, PortEntry b) => a.number != b.number ? a.number.compareTo(b.number) : a.transport.compareTo(b.transport);
    int risk(PortEntry e) => e.detail?.risk?.order ?? 0;
    switch (sortBy) {
      case SortBy.port:
        hits.sort(byPort);
      case SortBy.risk:
        hits.sort((a, b) => risk(b) != risk(a) ? risk(b).compareTo(risk(a)) : byPort(a, b));
      case SortBy.relevance:
        hits.sort((a, b) {
          final d = (scores?[b] ?? 0).compareTo(scores?[a] ?? 0);
          return d != 0 ? d : byPort(a, b);
        });
    }
    return hits;
  }
}

const _keep = Object();
const _classLabel = {PortClass.wellKnown: 'well-known', PortClass.registered: 'registered', PortClass.dynamic: 'dynamic'};
