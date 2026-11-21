// Null-tolerant JSON accessors: malformed data degrades to empty values
// instead of throwing, so the UI never crashes on a bad record.

typedef Json = Map<String, dynamic>;

String str(Object? v) => v is String ? v : (v == null ? '' : '$v');
int intOr(Object? v, [int fallback = -1]) => v is int ? v : fallback;
List<String> strs(Object? v) => v is List ? v.whereType<String>().toList() : const [];
List<Json> maps(Object? v) => v is List ? v.whereType<Json>().toList() : const [];
Json obj(Object? v) => v is Json ? v : const {};
List<List<dynamic>> rows(Object? v) => v is List ? v.whereType<List<dynamic>>().toList() : const [];

/// Lower-cases and folds full-width ASCII and the ideographic space so
/// "３３８９" and "ＴＣＰ" match "3389" and "tcp".
String normalizeText(String input) {
  final b = StringBuffer();
  for (final r in input.runes) {
    if (r >= 0xFF01 && r <= 0xFF5E) {
      b.writeCharCode(r - 0xFEE0);
    } else if (r == 0x3000) {
      b.write(' ');
    } else {
      b.writeCharCode(r);
    }
  }
  return b.toString().toLowerCase();
}
