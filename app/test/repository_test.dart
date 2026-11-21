import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:port_security/data/repository.dart';
import 'package:port_security/data/text.dart';

void main() {
  late PortRepository repo;
  setUpAll(() => repo = PortRepository.fromJsonString(File('assets/data/port_index.json').readAsStringSync()));

  List<String> labels(String q) => repo.search(q).map((p) => p.label).toList();

  group('data', () {
    test('all 51 ports load with ids and numbers', () {
      expect(repo.ports.length, 51);
      expect(repo.ports.every((p) => p.id.startsWith('PORT-') && p.number > 0), isTrue);
      expect(repo.ports.map((p) => p.id).toSet().length, 51);
    });
    test('every port reaches attack pattern, technique and log', () {
      for (final p in repo.ports) {
        expect(p.attacks, isNotEmpty, reason: p.id);
        expect(p.techniques, isNotEmpty, reason: p.id);
        expect(p.logs, isNotEmpty, reason: p.id);
      }
    });
    test('all links are https', () {
      final urls = [for (final p in repo.ports) ...[...p.sources.map((s) => s.url), ...p.techniques.map((t) => t.url)]];
      expect(urls.every((u) => Uri.parse(u).scheme == 'https'), isTrue);
    });
  });

  group('search', () {
    test('empty query returns all ports sorted', () {
      final all = repo.search('  ');
      expect(all.length, 51);
      expect(all.first.number <= all.last.number, isTrue);
    });
    test('known port number matches exactly', () => expect(labels('3389'), ['3389/TCP', '3389/UDP']));
    test('full-width digits', () => expect(labels('３３８９'), ['3389/TCP', '3389/UDP']));
    test('transport filter, both orders', () {
      expect(labels('445/tcp'), ['445/TCP']);
      expect(labels('TCP 445'), ['445/TCP']);
      expect(labels('udp 53'), ['53/UDP']);
    });
    test('22 does not match CVE-2022 text', () => expect(labels('22'), ['22/TCP']));
    test('MITRE technique id', () => expect(labels('t1110'), contains('3389/TCP')));
    test('event id falls back to text search', () => expect(labels('4625'), contains('3389/TCP')));
    test('service nickname via formal name', () => expect(labels('rdp').take(2), ['3389/TCP', '3389/UDP']));
    test('port-specific match ranks above shared text',
        () => expect(labels('kerberoasting').take(2), ['88/TCP', '88/UDP']));
    test('no match', () => expect(repo.search('zzzz-no-such'), isEmpty));
    test('regex metacharacters are literal', () => expect(() => repo.search(r'(.*[\'), returnsNormally));
  });

  group('robustness', () {
    test('non-array JSON is rejected', () {
      expect(() => PortRepository.fromJsonString('{"a":1}'), throwsFormatException);
    });
    test('records with missing or wrong-typed fields do not throw', () {
      final r = PortRepository.fromJsonString('[{}, {"port_number":"x","logs":[1,{"match":null}],"risk":"bad"}, 5]');
      expect(r.ports.length, 2);
      expect(r.ports.every((p) => p.risk == null && p.number == -1), isTrue);
      expect(r.search('anything'), isEmpty);
    });
    test('normalizeText folds full-width and ideographic space', () {
      expect(normalizeText('ＴＣＰ　４４５'), 'tcp 445');
    });
  });

  group('groups', () {
    test('attack and log groups cover every port', () {
      expect(repo.attackGroups.length, 7);
      final inAttack = {for (final g in repo.attackGroups) ...g.ports.map((p) => p.id)};
      expect(inAttack.length, 51);
      expect(repo.logGroups.map((g) => g.id), contains('LOG-WIN-AN0327'));
    });
  });
}
