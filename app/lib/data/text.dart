/// Lower-cases and folds full-width ASCII (Ａ-ｚ, ０-９, ／ …) and the
/// ideographic space to half-width, so "３３８９" matches "3389".
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
