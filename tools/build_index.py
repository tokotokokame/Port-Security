#!/usr/bin/env python3
"""Build dist/port_index.json (one joined record per port) and docs/VALIDATION_REPORT.md.

Usage: python3 tools/build_index.py   (fails if validation fails)
"""
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from validate import load_all, validate

ROOT = Path(__file__).parent.parent
PICK = lambda r, keys: {k: r.get(k) for k in keys}
# log relevance, strongest first
MATCH = ["DET公式監視ポート一致", "DETサービス名から推定", "攻撃手法経由", "境界機器ログ(全ポート共通)"]


def build(db):
    ix = {f: {(r.get("id") or r.get("source_id")): r for r in db[f]} for f in db}
    parent = {s["id"]: t["id"] for t in db["mitre_techniques"] for s in t["subtechniques"]}
    out = []
    for p in db["ports"]:
        atks = [ix["attack_patterns"][a] for a in p["attack_pattern_ids"]]
        logs, match = {}, {}
        def add(lid, via, level):
            logs.setdefault(lid, set()).add(via); match[lid] = min(match.get(lid, 9), level)
        for d in db["detection_strategies"]:
            for a in d["analytics"]:
                if p["port_number"] in a["monitored_ports"]:
                    lv = 0 if a["port_basis"] == "official" else 1
                    for lid in a["log_investigation_ids"]: add(lid, f"{d['id']}/{a['id']}", lv)
        for a in atks:
            for lid in a["log_investigation_ids"]: add(lid, a["id"], 2)
        for l in db["log_investigation"]:
            if l["port_scope"] == "any": add(l["id"], "境界機器ログ(全ポート共通)", 3)
        techs = []
        for t in p["technique_ids"]:
            base = ix["mitre_techniques"][parent.get(t, t)]
            name = next((s["name"] for s in base["subtechniques"] if s["id"] == t), base["name"])
            techs.append({"id": t, "name": name, "parent": base["id"], "tactics": base["tactics"],
                          "url": "https://attack.mitre.org/techniques/" + t.replace(".", "/") + "/",
                          "detection_strategies": [PICK(ix["detection_strategies"][d], ["id", "name", "url"])
                                                   for d in base["detection_strategy_ids"]]})
        svc, risk = ix["services"].get(p["service_id"]), ix["port_risks"].get(p["risk_id"])
        src_ids = list(dict.fromkeys(p["source_ids"] + (risk or {}).get("source_ids", []) + (svc or {}).get("source_ids", [])
                                     + [f"SRC-MITRE-{t['parent']}" for t in techs]))
        gaps = []
        if not risk: gaps.append("リスク評価なし")
        if not svc: gaps.append("サービス辞書なし")
        if min(match.values(), default=9) > 1: gaps.append("DET監視ポートに一致するホストログなし")
        if p["certainty"] != "確認済み": gaps.append("攻撃・検知記述の一次資料未付与")
        rec = {k: v for k, v in p.items() if k not in ("attack_pattern_ids", "technique_ids", "source_ids")}
        rec.update(
            service=PICK(svc, ["id", "formal_name", "purpose", "investigation_checkpoints"]) if svc else None,
            risk=PICK(risk, ["id", "risk_level", "reason_targeted", "suspicious_indicators", "investigation_focus",
                             "mitigation_controls", "certainty"]) if risk else None,
            attack_patterns=[PICK(a, ["id", "attack_name", "attack_features", "detection_methods", "recommended_defenses"]) for a in atks],
            techniques=techs,
            logs=[dict(PICK(ix["log_investigation"][l], ["id", "platform", "detection_analytics", "investigation_procedure", "certainty"]),
                       match=MATCH[match[l]], via=sorted(v)) for l, v in sorted(logs.items(), key=lambda kv: (match[kv[0]], kv[0]))],
            sources=[PICK(ix["sources"][s], ["source_id", "title", "url", "scope"]) for s in src_ids],
            gaps=gaps)
        out.append(rec)
    return out


def report(db, index, errors, warnings):
    n = len(index); pct = lambda k: f"{k}/{n} ({k * 100 // n}%)"
    cnt = lambda pred: pct(sum(1 for r in index if pred(r)))
    rows = [("攻撃手法あり", cnt(lambda r: r["attack_patterns"])), ("MITRE技術あり", cnt(lambda r: r["techniques"])),
            ("検知戦略(DET)まで到達", cnt(lambda r: any(t["detection_strategies"] for t in r["techniques"]))),
            ("ホストログ(DET監視ポート一致・推定含む)", cnt(lambda r: "DET監視ポートに一致するホストログなし" not in r["gaps"])),
            ("ログ調査(何らかの経路)", cnt(lambda r: r["logs"])),
            ("リスク評価", cnt(lambda r: r["risk"])), ("サービス辞書", cnt(lambda r: r["service"])),
            ("確認済み(脅威系一次資料あり)", cnt(lambda r: r["certainty"] == "確認済み"))]
    latest = max(r["verified_date"] for f, v in db.items() if f != "sources" for r in v)
    L = [f"# VALIDATION_REPORT（自動生成: tools/build_index.py）", "", f"- データ最終検証日: {latest}",
         f"- レコード総数: {sum(len(v) for v in db.values())}（" + ", ".join(f"{k} {len(v)}" for k, v in db.items()) + "）",
         f"- 整合性検証: **{'FAIL' if errors else 'PASS'}**（errors={len(errors)}, warnings={len(warnings)}）", "",
         "## ポート起点の到達率", "", "| 項目 | 件数 |", "|---|---|"] + [f"| {a} | {b} |" for a, b in rows]
    L += ["", "## ポート別の不足（データ追加の優先リスト）", "", "| ポート | サービス | 不足 |", "|---|---|---|"]
    L += [f"| {r['port_number']}/{r['transport_protocol']} | {r['service_name']} | {'、'.join(r['gaps'])} |" for r in index if r["gaps"]]
    L += ["", "## エラー・警告", ""] + [f"- ERROR {e}" for e in errors] + [f"- WARN {w}" for w in warnings] + (["- なし"] if not errors + warnings else [])
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    db = load_all(ROOT / "data")
    errors, warnings = validate(db)
    if errors:
        print("\n".join(errors)); print("validation failed; index not built"); sys.exit(1)
    index = build(db)
    (ROOT / "docs").mkdir(exist_ok=True); (ROOT / "dist").mkdir(exist_ok=True)
    (ROOT / "docs/VALIDATION_REPORT.md").write_text(report(db, index, errors, warnings), encoding="utf-8")
    (ROOT / "dist/port_index.json").write_text(json.dumps(index, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    app_asset = ROOT / "app/assets/data/port_index.json"  # compact copy bundled into the mobile app
    app_asset.parent.mkdir(parents=True, exist_ok=True)
    app_asset.write_text(json.dumps(index, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    print(f"dist/port_index.json: {len(index)} ports")
