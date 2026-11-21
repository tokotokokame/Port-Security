import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:port_security/data/filters.dart';
import 'package:port_security/data/json.dart';
import 'package:port_security/data/repository.dart';

Repository loadRepo() => Repository.fromStrings(File('assets/data/ports.json').readAsStringSync(),
    File('assets/data/kb.json').readAsStringSync(), File('assets/data/iana.json').readAsStringSync());

void main() {
  late Repository repo;
  setUpAll(() => repo = loadRepo());
  List<String> labels(String q, [SearchFilter f = const SearchFilter()]) => repo.search(q, f).map((e) => e.label).toList();

  group('data', () {
    test('two layers load: 160 detailed + IANA registry', () {
      expect(repo.detailed.length, 160);
      expect(repo.entries.length, greaterThan(11000));
      expect({for (final e in repo.entries) e.label}.length, repo.entries.length, reason: 'no duplicate port/transport');
    });
    test('every detailed port links attack, technique and log that exist in kb', () {
      for (final e in repo.detailed) {
        final d = e.detail!;
        expect(d.attacks.every(repo.attacks.containsKey), isTrue, reason: e.label);
        expect(d.techniques.every(repo.techniques.containsKey), isTrue, reason: e.label);
        expect(d.logs.every((l) => repo.logs.containsKey(l.id)), isTrue, reason: e.label);
        expect(d.tools.every(repo.tools.containsKey), isTrue, reason: e.label);
      }
    });
    test('new requests are present', () {
      expect(repo.logs.values.map((l) => l.platform).join(' '), allOf(contains('Hyper-V'), contains('VirtualBox')));
      expect(repo.tools.values.map((t) => t.name), containsAll(['Impacket', 'smbclient (Samba)', 'Mimikatz']));
      expect(repo.attacks.length, greaterThanOrEqualTo(20));
    });
    test('reviewed evidence is attached and resolvable', () {
      final withEv = repo.detailed.where((e) => e.detail!.evidence.isNotEmpty).toList();
      expect(withEv.length, greaterThanOrEqualTo(40));
      for (final e in withEv) {
        expect(e.detail!.evidence.every((x) => repo.sources.containsKey(x.source)), isTrue, reason: e.label);
      }
      final docker = repo.detailed.firstWhere((e) => e.label == '2375/tcp').detail!;
      expect(docker.certainty, '確認済み');
      expect(docker.evidence.map((x) => x.source), contains('SRC-DOCKER-REMOTE'));
    });
    test('all links are https', () {
      final urls = [...repo.sources.values.map((s) => s.url), ...repo.techniques.values.map((t) => t.url)];
      expect(urls.every((u) => Uri.parse(u).scheme == 'https'), isTrue);
    });
  });

  group('search', () {
    test('known port number matches exactly', () => expect(labels('3389'), ['3389/tcp', '3389/udp']));
    test('full-width input', () => expect(labels('３３８９　ｔｃｐ'), ['3389/tcp']));
    test('transport token both orders', () {
      expect(labels('445/tcp'), ['445/tcp']);
      expect(labels('UDP 53'), ['53/udp']);
    });
    test('IANA-only port is searchable', () => expect(labels('31337'), isNotEmpty));
    test('event id from ATT&CK/Sigma text', () => expect(labels('4769'), contains('88/tcp')));
    test('tool name finds its ports', () => expect(labels('impacket'), contains('445/tcp')));
    test('regex metacharacters are literal', () => expect(() => repo.search(r'(.*[\'), returnsNormally));
    test('no match', () => expect(labels('zzzz-no-such-term'), isEmpty));
  });

  group('filters', () {
    test('detail-only excludes IANA entries', () {
      expect(repo.search('', const SearchFilter(detailOnly: true)).length, 160);
    });
    test('risk >= Critical, sorted by risk', () {
      final r = repo.search('', const SearchFilter(minRisk: 'Critical', sortBy: SortBy.risk));
      expect(r, isNotEmpty);
      expect(r.every((e) => e.detail!.risk!.level == 'Critical'), isTrue);
    });
    test('tool + transport + range combine', () {
      final r = repo.search('', const SearchFilter(tool: 'TOOL-IMPACKET', transport: 'TCP', minPort: 400, maxPort: 500));
      expect(r.map((e) => e.label), ['445/tcp']);
    });
    test('log filter: Hyper-V ports', () {
      expect(repo.search('', const SearchFilter(log: 'LOG-HYPERV')).map((e) => e.number), containsAll([2179, 6600, 3343]));
    });
    test('tactic and port class', () {
      final r = repo.search('', const SearchFilter(tactic: 'credential-access', portClass: PortClass.wellKnown));
      expect(r, isNotEmpty);
      expect(r.every((e) => e.number < 1024), isTrue);
    });
    test('activeCount and copyWith clearing', () {
      const f = SearchFilter(transport: 'TCP', detailOnly: true);
      expect(f.activeCount, 2);
      expect(f.copyWith(transport: null).activeCount, 1);
    });
  });

  group('robustness', () {
    test('wrong top-level shapes are rejected', () {
      expect(() => Repository.fromStrings('{}', '{}', '[]'), throwsFormatException);
    });
    test('malformed records do not throw', () {
      final r = Repository.fromStrings('[{}, {"n":"x","risk":"bad","logs":[1]}, 3]', '{"attacks":{"A":5,"B":{}}}', '[[1],[2,"TCP","x","y",""]]');
      expect(r.entries, isNotEmpty);
      expect(r.attacks.keys, ['B']);
      expect(() => r.search('anything'), returnsNormally);
    });
    test('normalizeText', () => expect(normalizeText('ＴＣＰ　４４５'), 'tcp 445'));
  });
}
