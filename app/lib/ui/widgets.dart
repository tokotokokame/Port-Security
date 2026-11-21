import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:url_launcher/url_launcher.dart';

import '../data/models.dart';
import 'port_detail_screen.dart';

/// Opens only https links from the bundled data; anything else is refused.
/// If no browser can handle it, the URL is copied instead.
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
    messenger.showSnackBar(const SnackBar(content: Text('ブラウザを開けないため、URLをコピーしました')));
  }
}

void openPort(BuildContext context, PortEntry p) => Navigator.of(context).push(
      MaterialPageRoute<void>(builder: (_) => PortDetailScreen(entry: p)),
    );

Color riskColor(String level, ColorScheme cs) => switch (level) {
      'Critical' => Colors.red.shade700,
      'High' => Colors.orange.shade800,
      'Medium' => Colors.amber.shade800,
      'Low' => Colors.green.shade700,
      _ => cs.outline,
    };

class Pill extends StatelessWidget {
  const Pill(this.text, {super.key, this.color});
  final String text;
  final Color? color;

  @override
  Widget build(BuildContext context) {
    final c = color ?? Theme.of(context).colorScheme.outline;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
      decoration: BoxDecoration(
        color: c.withValues(alpha: 0.12),
        border: Border.all(color: c),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Text(text, style: TextStyle(fontSize: 12, color: c, fontWeight: FontWeight.w600)),
    );
  }
}

class RiskPill extends StatelessWidget {
  const RiskPill(this.risk, {super.key});
  final Risk? risk;

  @override
  Widget build(BuildContext context) => Pill(
        risk == null ? 'リスク未評価' : risk!.level,
        color: riskColor(risk?.level ?? '', Theme.of(context).colorScheme),
      );
}

class PortTile extends StatelessWidget {
  const PortTile(this.entry, {super.key, this.trailingNote});
  final PortEntry entry;
  final String? trailingNote;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return ListTile(
      leading: CircleAvatar(
        backgroundColor: cs.primaryContainer,
        child: FittedBox(
          child: Padding(
            padding: const EdgeInsets.all(4),
            child: Text('${entry.number}', style: TextStyle(color: cs.onPrimaryContainer, fontWeight: FontWeight.bold)),
          ),
        ),
      ),
      title: Text('${entry.label}  ${entry.service}'),
      subtitle: Text(trailingNote ?? entry.formalName, maxLines: 2, overflow: TextOverflow.ellipsis),
      trailing: RiskPill(entry.risk),
      onTap: () => openPort(context, entry),
    );
  }
}

/// Titled block used on detail screens. Empty bodies are hidden.
class Section extends StatelessWidget {
  const Section(this.title, {super.key, required this.children, this.icon});
  final String title;
  final IconData? icon;
  final List<Widget> children;

  @override
  Widget build(BuildContext context) {
    if (children.isEmpty) return const SizedBox.shrink();
    final t = Theme.of(context);
    return Card(
      margin: const EdgeInsets.fromLTRB(12, 6, 12, 6),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [
            if (icon != null) ...[Icon(icon, size: 20, color: t.colorScheme.primary), const SizedBox(width: 8)],
            Expanded(child: Text(title, style: t.textTheme.titleMedium?.copyWith(fontWeight: FontWeight.bold))),
          ]),
          const SizedBox(height: 8),
          ...children,
        ]),
      ),
    );
  }
}

/// Label + selectable value; renders nothing when the value is empty.
class Field extends StatelessWidget {
  const Field(this.label, this.value, {super.key});
  final String label, value;

  @override
  Widget build(BuildContext context) {
    if (value.trim().isEmpty) return const SizedBox.shrink();
    final t = Theme.of(context).textTheme;
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text(label, style: t.labelMedium?.copyWith(color: Theme.of(context).colorScheme.primary)),
        const SizedBox(height: 2),
        SelectableText(value, style: t.bodyMedium),
      ]),
    );
  }
}
