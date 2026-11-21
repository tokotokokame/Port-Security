import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:url_launcher/url_launcher.dart';

import '../data/models.dart';
import 'theme.dart';

/// Opens only https links from bundled data; otherwise copies the URL.
Future<void> openLink(BuildContext context, String url) async {
  final uri = Uri.tryParse(url);
  final messenger = ScaffoldMessenger.of(context);
  if (uri == null || uri.scheme != 'https' || uri.host.isEmpty) {
    messenger.showSnackBar(const SnackBar(content: Text('このリンクは開けません')));
    return;
  }
  var ok = false;
  try {
    ok = await launchUrl(uri, mode: LaunchMode.externalApplication);
  } catch (_) {
    ok = false;
  }
  if (!ok) {
    await Clipboard.setData(ClipboardData(text: url));
    messenger.showSnackBar(const SnackBar(content: Text('ブラウザを開けないため URL をコピーしました')));
  }
}

void push(BuildContext context, Widget page) => Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => page));

EdgeInsets listPadding(BuildContext context) => EdgeInsets.fromLTRB(0, 4, 0, 24 + MediaQuery.paddingOf(context).bottom);

class Tag extends StatelessWidget {
  const Tag(this.text, {super.key, this.color = Term.dim, this.filled = false});
  final String text;
  final Color color;
  final bool filled;

  @override
  Widget build(BuildContext context) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
        decoration: BoxDecoration(color: filled ? color : null, border: Border.all(color: color), borderRadius: BorderRadius.circular(3)),
        child: Text(text, style: Term.monoStyle(size: 11, color: filled ? Term.bg : color, weight: FontWeight.w700)),
      );
}

class RiskTag extends StatelessWidget {
  const RiskTag(this.risk, {super.key});
  final Risk? risk;

  @override
  Widget build(BuildContext context) => risk == null
      ? const Tag('—')
      : Tag(risk!.level == 'Critical' ? 'CRIT' : risk!.level.toUpperCase(), color: Term.risk(risk!.level), filled: risk!.order >= 3);
}

/// "# title" block. Hidden when it has nothing to show.
class TermSection extends StatelessWidget {
  const TermSection(this.title, {super.key, required this.children, this.note});
  final String title;
  final String? note;
  final List<Widget> children;

  @override
  Widget build(BuildContext context) {
    if (children.isEmpty) return const SizedBox.shrink();
    return Padding(
      padding: const EdgeInsets.fromLTRB(14, 12, 14, 4),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text.rich(TextSpan(children: [
          TextSpan(text: '# $title', style: Term.monoStyle(size: 13, color: Term.amber, weight: FontWeight.w700)),
          if (note != null) TextSpan(text: '  $note', style: Term.monoStyle(size: 11, color: Term.dim)),
        ])),
        const SizedBox(height: 6),
        ...children,
      ]),
    );
  }
}

/// Label/value pair; renders nothing when the value is blank.
class KV extends StatelessWidget {
  const KV(this.label, this.value, {super.key, this.mono = false});
  final String label, value;
  final bool mono;

  @override
  Widget build(BuildContext context) {
    if (value.trim().isEmpty) return const SizedBox.shrink();
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text(label, style: Term.monoStyle(size: 11, color: Term.teal)),
        SelectableText(value, style: mono ? Term.monoStyle(color: Term.text) : const TextStyle(fontSize: 13, height: 1.5, color: Term.text)),
      ]),
    );
  }
}

/// Left-ruled card used for attacks, tools, logs and techniques.
class RuleCard extends StatelessWidget {
  const RuleCard({super.key, required this.title, this.trailing, this.subtitle, this.onTap, this.children = const []});
  final String title;
  final String? trailing, subtitle;
  final VoidCallback? onTap;
  final List<Widget> children;

  @override
  Widget build(BuildContext context) => InkWell(
        onTap: onTap,
        child: Container(
          width: double.infinity,
          constraints: const BoxConstraints(minHeight: 44),
          margin: const EdgeInsets.only(bottom: 8),
          padding: const EdgeInsets.fromLTRB(10, 4, 4, 4),
          decoration: const BoxDecoration(border: Border(left: BorderSide(color: Term.line, width: 2))),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(title, style: Term.monoStyle(color: Term.bright, weight: FontWeight.w700))),
              if (trailing != null) Text(trailing!, style: Term.monoStyle(size: 11, color: Term.dim)),
              if (onTap != null) const Icon(Icons.chevron_right, size: 18, color: Term.dim),
            ]),
            if (subtitle != null && subtitle!.isNotEmpty) Text(subtitle!, style: const TextStyle(fontSize: 12, color: Term.dim, height: 1.45)),
            ...children,
          ]),
        ),
      );
}

class Bullet extends StatelessWidget {
  const Bullet(this.text, {super.key, this.color = Term.text});
  final String text;
  final Color color;

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.only(top: 2, bottom: 2),
        child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('- ', style: Term.monoStyle(color: Term.dim)),
          Expanded(child: SelectableText(text, style: TextStyle(fontSize: 12, height: 1.45, color: color))),
        ]),
      );
}
