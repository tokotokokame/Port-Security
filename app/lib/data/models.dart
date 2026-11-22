import 'json.dart';

const riskOrder = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4};

class Attack {
  Attack(this.id, Json j)
      : name = str(j['name']), category = str(j['category']), description = str(j['description']),
        features = str(j['features']), detection = str(j['detection']), defenses = str(j['defenses']),
        techniques = strs(j['techniques']), logs = strs(j['logs']), sources = strs(j['sources']),
        certainty = str(j['certainty']), notes = str(j['notes']), verified = str(j['verified']),
        mapping = str(j['mapping']), content = str(j['content']), relation = str(j['relation']);
  final String id, name, category, description, features, detection, defenses, certainty, notes, verified;
  /// v1.2: ATT&CK 技術への対応付けと本文の確認状態を分けて持つ。relation は generic / service_specific。
  final String mapping, content, relation;
  final List<String> techniques, logs, sources;
}

class Technique {
  Technique(this.id, Json j)
      : name = str(j['name']), url = str(j['url']), parent = j['parent'] as String?,
        tactics = strs(j['tactics']), dets = strs(j['dets']);
  final String id, name, url;
  final String? parent;
  final List<String> tactics, dets;
}

class Analytic {
  Analytic(Json j)
      : id = str(j['id']), platforms = strs(j['platforms']), description = str(j['description']),
        logs = [for (final r in rows(j['logs'])) '${str(r.isNotEmpty ? r[0] : '')}  ${str(r.length > 1 ? r[1] : '')}'];
  final String id, description;
  final List<String> platforms, logs;
}

class Det {
  Det(this.id, Json j) : name = str(j['name']), url = str(j['url']), analytics = maps(j['analytics']).map(Analytic.new).toList();
  final String id, name, url;
  final List<Analytic> analytics;
}

class Tool {
  Tool(this.id, Json j)
      : name = str(j['name']), category = str(j['category']), sid = j['sid'] as String?, summary = str(j['summary']),
        ports = [for (final r in rows(j['ports'])) if (r.length == 2) '${r[0]}/${str(r[1]).toLowerCase()}'],
        artifacts = strs(j['artifacts']), detection = strs(j['detection']), attacks = strs(j['attacks']),
        techniques = strs(j['techniques']), logs = strs(j['logs']), sources = strs(j['sources']),
        stixTechniques = strs(j['techniques_stix']), appTechniques = strs(j['techniques_app']),
        certainty = str(j['certainty']), notes = str(j['notes']), verified = str(j['verified']);
  final String id, name, category, summary, certainty, notes, verified;
  final String? sid;
  /// stixTechniques = ATT&CK 公式の uses 関係 / appTechniques = アプリ内の関連付け（攻撃手法経由）
  final List<String> ports, artifacts, detection, attacks, techniques, logs, sources, stixTechniques, appTechniques;
}

class LogSource {
  LogSource(this.id, Json j)
      : platform = str(j['platform']), analytics = str(j['analytics']), procedure = str(j['procedure']),
        certainty = str(j['certainty']), notes = str(j['notes']), refs = strs(j['refs']), verified = str(j['verified']),
        channels = [for (final r in rows(j['sources'])) if (r.length == 3) (str(r[0]), r[1] is int ? r[1] as int : null, str(r[2]))],
        scope = str(j['scope']), vendor = [for (final r in rows(j['vendor'])) if (r.length == 9) VendorLog(r)];
  final String id, platform, analytics, procedure, certainty, notes, verified, scope;
  final List<String> refs;
  final List<(String, int?, String)> channels;
  final List<VendorLog> vendor;
}

/// Vendor log definition with its own version and source (v1.2).
class VendorLog {
  VendorLog(List<dynamic> r)
      : versions = str(r[0]), type = str(r[1]), subtype = str(r[2]), id = str(r[3]), message = str(r[4]),
        fields = strs(r[5]), cli = strs(r[6]), status = str(r[7]), notes = str(r[8]);
  final String versions, type, subtype, id, message, status, notes;
  final List<String> fields, cli;
}

class Source {
  Source(this.id, Json j)
      : title = str(j['title']), url = str(j['url']), publisher = str(j['publisher']), verified = j['verified'] == true,
        certainty = str(j['certainty']), checked = str(j['checked']), via = str(j['via']);
  final String id, title, url, publisher, certainty, checked, via;
  static const viaLabels = {'original_document': '原文', 'official_api': '公式API', 'official_stix': '公式STIX',
    'official_repository': '公式リポジトリ', 'search_result': '検索結果のみ', 'not_verified': '未確認'};
  String get viaLabel => viaLabels[via] ?? via;
  final bool verified;
}

/// CVE managed through product / version / configuration — never by port number alone.
class Vuln {
  Vuln(this.id, Json j)
      : title = str(j['title']), condition = str(j['condition']), published = str(j['published']), updated = str(j['updated']),
        kev = j['kev'] == true, kevAdded = str(j['kev_added']), notes = str(j['notes']), verified = str(j['verified']),
        refs = strs(j['refs']), sources = strs(j['sources']),
        cvss = [for (final r in rows(j['cvss'])) if (r.length == 4) (r[0] is num ? (r[0] as num).toDouble() : 0.0, str(r[1]), str(r[2]), str(r[3]))],
        affected = [for (final r in rows(j['affected'])) if (r.length == 4) (str(r[0]), str(r[1]), strs(r[2]), strs(r[3]))];
  final String id, title, condition, published, updated, kevAdded, notes, verified;
  final bool kev;
  final List<String> refs, sources;
  final List<(double, String, String, String)> cvss;
  final List<(String, String, List<String>, List<String>)> affected;
  double get score => cvss.isEmpty ? 0 : cvss.first.$1;
}

/// Why a port is linked to an ATT&CK technique (direct / generic / inferred / unverified).
class Basis {
  Basis(Json j) : relation = str(j['relation']), via = strs(j['via']), note = str(j['note']), sourceType = str(j['source_type']);
  final String relation, note, sourceType;
  final List<String> via;
  static const labels = {'direct': '直接（ポート固有の根拠）', 'generic': '汎用（どの公開サービスにも当てはまる）',
    'inferred': '推定（サービスの性質から）', 'unverified': '未確認（参考）',
    // v1.1 の区分（古いデータ用）
    'attack_pattern': '攻撃手法経由', 'service': 'サービス経由', 'reference': '参考'};
  static const sourceLabels = {'stix': 'ATT&CK 公式の記述', 'document': '一次資料', 'curation': 'アプリ内の関連付け'};
  String get label => labels[relation] ?? relation;
  String get sourceLabel => sourceLabels[sourceType] ?? sourceType;
}

class LogRef {
  LogRef(Json j) : id = str(j['id']), match = str(j['match']), rank = intOr(j['rank'], 9), via = strs(j['via']), cls = str(j['class']);
  /// cls: A / B はポート固有、B' はプラットフォーム共通、C/D は境界機器・攻撃手法経由
  final String id, match, cls;
  final int rank;
  final List<String> via;
}

class Risk {
  Risk(Json j)
      : level = str(j['level']), reason = str(j['reason']), indicators = str(j['indicators']),
        focus = str(j['focus']), mitigation = str(j['mitigation']), certainty = str(j['certainty']),
        notes = str(j['notes']), verified = str(j['verified']), vulns = strs(j['vulns']),
        serviceLevel = str(obj(j['service'])['level']), serviceReason = str(obj(j['service'])['reason']),
        serviceStatus = str(obj(j['service'])['status']), serviceSources = strs(obj(j['service'])['source_ids']),
        exposure = str(obj(j['exposure'])['assumed']), raises = strs(obj(j['exposure'])['raises']), lowers = strs(obj(j['exposure'])['lowers']);
  final String level, reason, indicators, focus, mitigation, certainty, notes, verified;
  /// v1.2: サービス固有のリスク（一次資料の要素だけで判定）と露出条件を risk level と分けて持つ
  final String serviceLevel, serviceReason, serviceStatus, exposure;
  final List<String> vulns, serviceSources, raises, lowers;
  int get order => riskOrder[level] ?? 0;
  static const exposureLabels = {'internet': 'インターネットから到達可能', 'untrusted_network': '信頼できないネットワークから到達可能',
    'internal_only': '内部ネットワークのみ', 'management_network_only': '管理ネットワークのみ', 'firewall_restricted': 'FW で送信元を制限',
    'auth_access_control': '認証・アクセス制御を適用'};
  static String ex(String c) => exposureLabels[c] ?? c;
}

/// Detailed knowledge for a port (absent for IANA-only entries).
class Detail {
  Detail(Json j)
      : name = str(j['name']), category = str(j['category']), purpose = str(j['purpose']), technical = str(j['technical']),
        normal = str(j['normal']), malicious = str(j['malicious']), suspicious = str(j['suspicious']),
        checkpoints = str(j['checkpoints']), defenses = str(j['defenses']), certainty = str(j['certainty']),
        notes = str(j['notes']), verified = str(j['verified']),
        risk = j['risk'] is Json ? Risk(j['risk'] as Json) : null,
        attacks = strs(j['attacks']), techniques = strs(j['techniques']), tools = strs(j['tools']),
        logs = maps(j['logs']).map(LogRef.new).toList(), sources = strs(j['sources']), gaps = strs(j['gaps']),
        evidence = maps(j['evidence']).map(Evidence.new).toList(),
        basis = {for (final e in obj(j['basis']).entries) if (e.value is Json) e.key: Basis(e.value as Json)};
  final String name, category, purpose, technical, normal, malicious, suspicious, checkpoints, defenses, certainty, notes, verified;
  final Risk? risk;
  final List<String> attacks, techniques, tools, sources, gaps;
  final List<LogRef> logs;
  final List<Evidence> evidence;
  final Map<String, Basis> basis;
}

/// Reviewed proof that a source supports this port's claim.
class Evidence {
  Evidence(Json j)
      : source = str(j['source']), kind = str(j['kind']), technique = str(j['technique']),
        examples = strs(j['examples']), summary = str(j['summary']);
  final String source, kind, technique, summary;
  final List<String> examples;
}

class PortEntry {
  PortEntry({required this.number, required this.transport, required this.service, this.iana = '', this.unauthorized = '', this.detail});
  final int number;
  final String transport, service, iana, unauthorized;
  final Detail? detail;

  String get label => '$number/${transport.toLowerCase()}';
  String get title => detail?.name.isNotEmpty == true ? detail!.name : (iana.isNotEmpty ? iana : service);
  String get portClass => number < 1024 ? 'well-known' : (number < 49152 ? 'registered' : 'dynamic');

  late final String nameText = normalizeText('$service $title');
  late final String ownText = normalizeText([
    service, iana, unauthorized,
    if (detail != null) ...[detail!.name, detail!.category, detail!.purpose, detail!.malicious, detail!.suspicious,
      detail!.checkpoints, detail!.defenses, detail!.risk?.level ?? '', ...detail!.techniques],
  ].join('\n'));
}
