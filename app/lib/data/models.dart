import 'json.dart';

const riskOrder = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4};

class Attack {
  Attack(this.id, Json j)
      : name = str(j['name']), category = str(j['category']), description = str(j['description']),
        features = str(j['features']), detection = str(j['detection']), defenses = str(j['defenses']),
        techniques = strs(j['techniques']), logs = strs(j['logs']), sources = strs(j['sources']);
  final String id, name, category, description, features, detection, defenses;
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
        certainty = str(j['certainty']), notes = str(j['notes']);
  final String id, name, category, summary, certainty, notes;
  final String? sid;
  final List<String> ports, artifacts, detection, attacks, techniques, logs, sources;
}

class LogSource {
  LogSource(this.id, Json j)
      : platform = str(j['platform']), analytics = str(j['analytics']), procedure = str(j['procedure']),
        certainty = str(j['certainty']), notes = str(j['notes']), refs = strs(j['refs']),
        channels = [for (final r in rows(j['sources'])) if (r.length == 3) (str(r[0]), r[1] is int ? r[1] as int : null, str(r[2]))];
  final String id, platform, analytics, procedure, certainty, notes;
  final List<String> refs;
  final List<(String, int?, String)> channels;
}

class Source {
  Source(this.id, Json j) : title = str(j['title']), url = str(j['url']), publisher = str(j['publisher']), verified = j['verified'] == true;
  final String id, title, url, publisher;
  final bool verified;
}

class LogRef {
  LogRef(Json j) : id = str(j['id']), match = str(j['match']), rank = intOr(j['rank'], 9), via = strs(j['via']);
  final String id, match;
  final int rank;
  final List<String> via;
}

class Risk {
  Risk(Json j)
      : level = str(j['level']), reason = str(j['reason']), indicators = str(j['indicators']),
        focus = str(j['focus']), mitigation = str(j['mitigation']);
  final String level, reason, indicators, focus, mitigation;
  int get order => riskOrder[level] ?? 0;
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
        evidence = maps(j['evidence']).map(Evidence.new).toList();
  final String name, category, purpose, technical, normal, malicious, suspicious, checkpoints, defenses, certainty, notes, verified;
  final Risk? risk;
  final List<String> attacks, techniques, tools, sources, gaps;
  final List<LogRef> logs;
  final List<Evidence> evidence;
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
