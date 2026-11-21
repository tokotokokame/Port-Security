// Typed, null-tolerant views over assets/data/port_index.json.
// Every accessor falls back to an empty value so a malformed record
// can never crash the UI.
import 'text.dart';

String _s(Object? v) => v is String ? v : (v == null ? '' : '$v');
List<Map<String, dynamic>> _maps(Object? v) =>
    v is List ? v.whereType<Map<String, dynamic>>().toList() : const [];
List<String> _strs(Object? v) =>
    v is List ? v.whereType<String>().toList() : const [];

class NamedLink {
  const NamedLink(this.id, this.name, this.url);
  final String id, name, url;
  factory NamedLink.fromJson(Map<String, dynamic> j) =>
      NamedLink(_s(j['id'] ?? j['source_id']), _s(j['name'] ?? j['title']), _s(j['url']));
}

class Technique {
  Technique.fromJson(Map<String, dynamic> j)
      : id = _s(j['id']),
        name = _s(j['name']),
        tactics = _strs(j['tactics']),
        url = _s(j['url']),
        detections = _maps(j['detection_strategies']).map(NamedLink.fromJson).toList();
  final String id, name, url;
  final List<String> tactics;
  final List<NamedLink> detections;
}

class AttackRef {
  AttackRef.fromJson(Map<String, dynamic> j)
      : id = _s(j['id']),
        name = _s(j['attack_name']),
        features = _s(j['attack_features']),
        detection = _s(j['detection_methods']),
        defenses = _s(j['recommended_defenses']);
  final String id, name, features, detection, defenses;
}

class LogRef {
  LogRef.fromJson(Map<String, dynamic> j)
      : id = _s(j['id']),
        platform = _s(j['platform']),
        analytics = _s(j['detection_analytics']),
        procedure = _s(j['investigation_procedure']),
        certainty = _s(j['certainty']),
        match = _s(j['match']),
        via = _strs(j['via']);
  final String id, platform, analytics, procedure, certainty, match;
  final List<String> via;

  /// 0 = strongest relevance. Mirrors MATCH order in tools/build_index.py.
  int get rank => switch (match) {
        'DET公式監視ポート一致' => 0,
        'DETサービス名から推定' => 1,
        '攻撃手法経由' => 2,
        _ => 3,
      };
}

class Risk {
  Risk.fromJson(Map<String, dynamic> j)
      : level = _s(j['risk_level']),
        reason = _s(j['reason_targeted']),
        indicators = _s(j['suspicious_indicators']),
        focus = _s(j['investigation_focus']),
        mitigation = _s(j['mitigation_controls']);
  final String level, reason, indicators, focus, mitigation;
}

class PortEntry {
  PortEntry.fromJson(Map<String, dynamic> j)
      : id = _s(j['id']),
        number = j['port_number'] is int ? j['port_number'] as int : -1,
        transport = _s(j['transport_protocol']),
        service = _s(j['service_name']),
        formalName = _s(j['formal_name']),
        purpose = _s(j['purpose']),
        technical = _s(j['technical_description']),
        normalUse = _s(j['normal_usage_examples']),
        malicious = _s(j['malicious_exploitation_cases']),
        suspicious = _s(j['suspicious_traffic_features']),
        checkpoints = _s(j['investigation_checkpoints']),
        defenses = _s(j['recommended_defenses']),
        certainty = _s(j['certainty']),
        notes = _s(j['unconfirmed_notes']),
        verifiedDate = _s(j['verified_date']),
        risk = j['risk'] is Map<String, dynamic> ? Risk.fromJson(j['risk'] as Map<String, dynamic>) : null,
        attacks = _maps(j['attack_patterns']).map(AttackRef.fromJson).toList(),
        techniques = _maps(j['techniques']).map(Technique.fromJson).toList(),
        logs = _maps(j['logs']).map(LogRef.fromJson).toList(),
        sources = _maps(j['sources']).map(NamedLink.fromJson).toList(),
        gaps = _strs(j['gaps']);

  final String id, transport, service, formalName, purpose, technical, normalUse,
      malicious, suspicious, checkpoints, defenses, certainty, notes, verifiedDate;
  final int number;
  final Risk? risk;
  final List<AttackRef> attacks;
  final List<Technique> techniques;
  final List<LogRef> logs;
  final List<NamedLink> sources;
  final List<String> gaps;

  String get label => '$number/$transport';

  /// Port-specific text (ranked higher in search).
  late final String ownText = [
    id, service, formalName, purpose, technical, malicious, suspicious, checkpoints, defenses,
    risk?.level, risk?.reason, risk?.indicators, risk?.focus,
    for (final t in techniques) ...[t.id, t.name, ...t.tactics, for (final d in t.detections) ...[d.id, d.name]],
  ].whereType<String>().map(normalizeText).join('\n');

  /// Everything searchable, including shared attack-pattern and log text.
  late final String searchText = [
    ownText,
    for (final a in attacks) ...[a.id, a.name, a.features, a.detection],
    for (final l in logs) ...[l.id, l.platform, l.analytics],
  ].map(normalizeText).join('\n');

  late final String nameText = normalizeText('$service $formalName');
}
