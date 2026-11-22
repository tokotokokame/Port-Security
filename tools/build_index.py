#!/usr/bin/env python3
"""Build app/dist assets and docs/VALIDATION_REPORT.md (fails if validation fails).

Outputs (same content in dist/ and app/assets/data/):
  ports.json  detailed ports with ID references and log relevance
  kb.json     attacks, techniques, detection strategies, tools, logs, sources
  iana.json   every IANA-registered port: [port, transport, names, description, unauthorized-use note]
"""
import csv, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from validate import load_all, validate
import reports

ROOT = Path(__file__).parent.parent
DATA_VERSION = "1.2"
MATCH = ["DET公式監視ポート一致", "公式文書のポート指定", "DETサービス名から推定", "ATT&CK検知戦略(プラットフォーム)",
         "攻撃手法・ツール経由", "境界機器ログ(全ポート共通)"]
# 5 章の分類: A=公式資料がポートを明示 / B=DET がポート・通信方式を示す / B'=プラットフォーム共通 / C/D=ベンダー・境界・攻撃手法経由
CLASS = ["B", "A", "B", "B'", "C/D", "C/D"]
PORT_SPECIFIC = {"A", "B"}  # ポート固有のログの有無は A と B だけで判定する（B' は数えない）


def build(db):
    ix = {f: {(r.get("id") or r.get("source_id")): r for r in db[f]} for f in db}
    parent = {s["id"]: t for t in db["mitre_techniques"] for s in t["subtechniques"]}
    det_of = {t["id"]: t["detection_strategy_ids"] for t in db["mitre_techniques"]}
    det_of.update({s["id"]: s["detection_strategy_ids"] for t in db["mitre_techniques"] for s in t["subtechniques"]})
    soft_tech = {s["id"]: s["technique_ids"] for s in db["mitre_software"]}
    tool_techs = {t["id"]: sorted(set(t["technique_ids"]) | set(soft_tech.get(t["mitre_software_id"], []))) for t in db["tools"]}
    vulns_of = {}
    for v in db["vulnerabilities"]:
        for r in v["risk_ids"]: vulns_of.setdefault(r, []).append(v["id"])
    tools_at = {}
    for t in db["tools"]:
        for n, tp in t["ports"]: tools_at.setdefault((n, tp), []).append(t["id"])
    ports = []
    for p in db["ports"]:
        key, logs, rank = (p["port_number"], p["transport_protocol"]), {}, {}
        def add(lid, via, lv):
            logs.setdefault(lid, set()).add(via); rank[lid] = min(rank.get(lid, 9), lv)
        for d in db["detection_strategies"]:
            for a in d["analytics"]:
                if list(key) in a["monitored_ports"]:  # (番号, 通信方式) で照合。番号だけの一致は使わない
                    for ln in a["log_links"]:  # DET0118 専用ログだけがポート固有（B）。同じ analytic のプラットフォーム共通ログは B'
                        add(ln["log_id"], f"{d['id']}/{a['id']}", (0 if a["port_basis"] == "official" else 2) if ln["basis"] == "det0118_analytic" else 3)
        for l in db["log_investigation"]:
            if l["port_scope"] == "listed" and list(key) in [list(x) for x in l["ports"]]: add(l["id"], "公式文書のポート指定", 1)
            if l["port_scope"] == "any": add(l["id"], "境界機器ログ(全ポート共通)", 5)
        for t in p["technique_ids"]:
            for did in det_of.get(t, []):
                for a in ix["detection_strategies"][did]["analytics"]:
                    for lid in a["log_investigation_ids"]: add(lid, f"{did}/{a['id']}", 3)
        tools = tools_at.get(key, [])
        for aid in p["attack_pattern_ids"]:
            for lid in ix["attack_patterns"][aid]["log_investigation_ids"]: add(lid, aid, 4)
        for tid in tools:
            for lid in ix["tools"][tid]["log_investigation_ids"]: add(lid, tid, 4)
        risk = ix["port_risks"].get(p["risk_id"])
        gaps = []
        if p["certainty"] != "確認済み": gaps.append("攻撃・検知記述の一次資料未付与")
        if not {CLASS[r] for r in rank.values()} & PORT_SPECIFIC: gaps.append("ポート固有のログなし（A・B なし）")
        if not risk: gaps.append("リスク評価なし")
        ports.append({
            "id": p["id"], "n": p["port_number"], "t": p["transport_protocol"], "service": p["service_name"],
            "name": p["formal_name"], "iana": p.get("iana_description", ""), "category": p["category"],
            "purpose": p["purpose"], "technical": p.get("technical_description", ""), "normal": p.get("normal_usage_examples", ""),
            "malicious": p["malicious_exploitation_cases"], "suspicious": p["suspicious_traffic_features"],
            "checkpoints": p["investigation_checkpoints"], "defenses": p["recommended_defenses"],
            "certainty": p["certainty"], "notes": p["unconfirmed_notes"], "verified": p["verified_date"],
            "risk": None if not risk else {"level": risk["risk_level"], "reason": risk["reason_targeted"],
                                           "indicators": risk.get("suspicious_indicators", ""), "focus": risk.get("investigation_focus", ""),
                                           "mitigation": risk.get("mitigation_controls", ""), "certainty": risk["certainty"],
                                           "notes": risk["unconfirmed_notes"], "verified": risk["verified_date"],
                                           "vulns": vulns_of.get(risk["id"], []),
                                           "service": {k: risk["service_risk"][k] for k in ("level", "reason", "status", "source_ids")} if "service_risk" in risk else None,
                                           "exposure": risk.get("exposure_condition")},
            "basis": {b["technique"]: {"relation": b["relation"], "via": b["via"], "note": b.get("note", ""), "source_type": b.get("source_type", "")}
                      for b in p["technique_basis"]},
            "attacks": p["attack_pattern_ids"], "techniques": p["technique_ids"], "tools": tools,
            "logs": [{"id": l, "match": MATCH[rank[l]], "rank": rank[l], "class": CLASS[rank[l]], "via": sorted(v)}
                     for l, v in sorted(logs.items(), key=lambda kv: (rank[kv[0]], kv[0]))],
            "log_class": min((CLASS[r] for r in rank.values()), key=["A", "B", "B'", "C/D"].index, default="なし"),
            "sources": list(dict.fromkeys(p["source_ids"] + (risk or {}).get("source_ids", []) +
                                          [f"SRC-MITRE-{t.split('.')[0]}" for t in p["technique_ids"]])),
            "evidence": [{"source": e["source_id"], "kind": e["kind"], "technique": e.get("technique"),
                          "examples": e.get("examples", []), "summary": e.get("keyword", "")} for e in p.get("evidence", [])],
            "gaps": gaps})
    techniques = {}
    for t in db["mitre_techniques"]:
        techniques[t["id"]] = {"name": t["name"], "tactics": t["tactics"], "url": t["url"], "parent": None, "dets": t["detection_strategy_ids"]}
        for s in t["subtechniques"]:
            techniques[s["id"]] = {"name": s["name"], "tactics": t["tactics"], "parent": t["id"], "dets": s["detection_strategy_ids"],
                                   "url": "https://attack.mitre.org/techniques/" + s["id"].replace(".", "/") + "/"}
    kb = {
        "attacks": {a["id"]: {"name": a["attack_name"], "category": a.get("category", ""), "description": a.get("description", ""),
                              "features": a.get("attack_features", ""), "detection": a["detection_methods"],
                              "defenses": a.get("recommended_defenses", ""), "techniques": a["technique_ids"],
                              "logs": a["log_investigation_ids"], "sources": a["source_ids"], "certainty": a["certainty"],
                              "notes": a["unconfirmed_notes"], "verified": a["verified_date"], "mapping": a.get("attack_mapping_status", ""),
                              "content": a.get("content_verification_status", ""), "relation": a.get("port_relation", "")} for a in db["attack_patterns"]},
        "techniques": techniques,
        "dets": {d["id"]: {"name": d["name"], "url": d["url"], "analytics": [
            {"id": a["id"], "platforms": a["platforms"], "description": a["description"],
             "logs": [[x["name"], x["channel"]] for x in a["log_sources"]]} for a in d["analytics"]]} for d in db["detection_strategies"]},
        "tools": {t["id"]: {"name": t["name"], "category": t["category"], "sid": t["mitre_software_id"], "summary": t["summary"],
                            "ports": t["ports"], "artifacts": t["artifacts"], "detection": t["detection"], "attacks": t["attack_pattern_ids"],
                            "techniques": tool_techs[t["id"]], "logs": t["log_investigation_ids"], "sources": t["source_ids"],
                            "techniques_stix": sorted(soft_tech.get(t["mitre_software_id"], [])),  # ATT&CK 公式の uses 関係
                            "techniques_app": sorted(set(t["technique_ids"]) - set(soft_tech.get(t["mitre_software_id"], []))),  # アプリ内の関連付け
                            "certainty": t["certainty"], "notes": t["unconfirmed_notes"], "verified": t["verified_date"]} for t in db["tools"]},
        "logs": {l["id"]: {"platform": l["platform"], "sources": [[s["channel"], s["event_code"], s["description"]] for s in l["log_sources"]],
                           "analytics": l.get("detection_analytics", ""), "procedure": l["investigation_procedure"],
                           "certainty": l["certainty"], "notes": l["unconfirmed_notes"], "refs": l["source_ids"], "scope": l["port_scope"],
                           "vendor": [[", ".join(v["firmware_versions"]), v["log_type"], v["log_subtype"], v["log_id"], v["message"], v["fields"],
                                       v["cli_commands"], v["verification_status"], v["notes"]] for v in l.get("vendor_logs", [])],
                           "verified": l["verified_date"]} for l in db["log_investigation"]},
        "sources": {s["source_id"]: {"title": s["title"], "url": s["url"], "publisher": s.get("publisher", ""),
                                     "scope": s["scope"], "verified": s["reverified_v4"], "certainty": s["verification_status"],
                                     "checked": s.get("access_date") or "", "via": s.get("verified_via", "")} for s in db["sources"]},
        "vulns": {v["id"]: {"title": v["title"], "condition": v["condition"], "published": v["published"], "updated": v["updated"],
                            "cvss": [[c["score"], c["version"], c["source"], c["vector"]] for c in v["cvss"]],
                            "kev": v["kev"]["listed"], "kev_added": v["kev"].get("date_added", ""),
                            "affected": [[a["vendor"], a["product"], a["versions"], a.get("fixed", [])] for a in v["affected"]],
                            "refs": v["references"], "sources": v["source_ids"], "notes": v["unconfirmed_notes"],
                            "verified": v["verified_date"]} for v in db["vulnerabilities"]},
        "software": {s["id"]: {"name": s["name"], "description": s["description"], "url": s["url"]} for s in db["mitre_software"]},
    }
    return ports, kb


def iana_rows():
    rows = {}
    for r in csv.DictReader(open(ROOT / "data/raw/iana/service-names-port-numbers.csv", encoding="utf-8", newline="")):
        name, num, tp = r["Service Name"].strip(), r["Port Number"].strip(), r["Transport Protocol"].upper()
        if not name or not num or tp not in ("TCP", "UDP", "SCTP", "DCCP"): continue
        lo, _, hi = num.partition("-")
        for n in range(int(lo), int(hi or lo) + 1):
            e = rows.setdefault((n, tp), [n, tp, [], r["Description"].strip(), r["Unauthorized Use Reported"].strip()])
            if name not in e[2]: e[2].append(name)
    return [[n, tp, " / ".join(names), d, u] for (n, tp), (_, _, names, d, u) in sorted(rows.items())]


def report(db, ports, iana, errors, warnings):
    n = len(ports); pct = lambda k: f"{k}/{n} ({k * 100 // n}%)"
    cnt = lambda pred: pct(sum(1 for r in ports if pred(r)))
    latest = max(r["verified_date"] for f, v in db.items() if f != "sources" for r in v)
    rows = [("攻撃手法あり", cnt(lambda r: r["attacks"])), ("MITRE技術あり", cnt(lambda r: r["techniques"])),
            ("攻撃ツールの紐付けあり", cnt(lambda r: r["tools"])),
            ("ホストログ(DET監視ポート・公式文書・推定・検知戦略)", cnt(lambda r: any(l["rank"] <= 3 for l in r["logs"]))),
            ("ログ調査(何らかの経路)", cnt(lambda r: r["logs"])), ("リスク評価", cnt(lambda r: r["risk"])),
            ("確認済み(脅威系一次資料あり)", cnt(lambda r: r["certainty"] == "確認済み"))]
    L = ["# VALIDATION_REPORT（自動生成: tools/build_index.py）", "", f"- データ最終検証日: {latest}",
         f"- 収録: 詳細付きポート {n} 件 / IANA 登録ポート {len(iana)} 件",
         "- レコード総数: " + ", ".join(f"{k} {len(v)}" for k, v in db.items()),
         f"- 整合性検証: **{'FAIL' if errors else 'PASS'}**（errors={len(errors)}, warnings={len(warnings)}）", "",
         "## 詳細付きポートの到達率", "", "| 項目 | 件数 |", "|---|---|"] + [f"| {a} | {b} |" for a, b in rows]
    L += ["", "## ポート別の不足（データ追加の優先リスト）", "", "| ポート | サービス | 不足 |", "|---|---|---|"]
    L += [f"| {r['n']}/{r['t']} | {r['service']} | {'、'.join(r['gaps'])} |" for r in ports if r["gaps"]]
    L += ["", "## エラー・警告", ""] + [f"- ERROR {e}" for e in errors] + [f"- WARN {w}" for w in warnings] + (["- なし"] if not errors + warnings else [])
    return "\n".join(L) + "\n"


def quality_section(db):
    import quality
    from collections import Counter
    res = quality.run(db)
    c = Counter((r["code"], r["level"]) for r in res)
    codes = ["Q-JSON", "Q-SCHEMA", "Q-DUP", "Q-ATTACK", "Q-TRANSPORT", "Q-IPPROTO", "Q-IANA", "Q-VERIFIED", "Q-SRC", "Q-HIDDEN",
             "Q-ASSOC", "Q-CVE", "Q-COUNT", "Q-VIA", "Q-SCOPE", "Q-ATTR", "Q-STAT", "Q-REVIEW", "Q-RISK", "Q-VENDOR", "Q-LOGLINK", "Q-LOGCLASS"]
    L = ["", "## 品質基準（tools/quality.py / docs/DATA_QUALITY_STANDARD.md）", "", "| コード | error |", "|---|---|"]
    L += [f"| {k} | {c[(k, 'error')]} |" for k in codes]
    info = [f"- {r['where']}: {r['msg']}" for r in res if r["level"] == "info"]
    if info: L += ["", "対象外（記録のみ）:"] + info
    import metrics
    base_p = ROOT / "docs/metrics/v1.1.json"
    base = json.loads(base_p.read_text(encoding="utf-8")) if base_p.exists() else {}
    dist = json.loads((ROOT / "dist/ports.json").read_text(encoding="utf-8"))
    cat = json.loads((ROOT / "data/raw/mitre/attack_catalog.json").read_text(encoding="utf-8"))
    L += ["", "## 指標（tools/metrics.py。v1.1 は main @ 09b8014 で同じ定義により算出した値）", ""] + metrics.table(metrics.compute(db, dist, cat), base)
    L += ["", "- 「ポート固有ログなし」は A・B だけで判定する（v1.2 の定義）。v1.1 のアプリは B' も数えていたため、画面上の件数は 11 だった。",
          "- ATT&CK 関連の区分は v1.2 で direct / generic / inferred / unverified に変更（v1.1 の attack_pattern・service・reference は旧区分）。"]
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    db = load_all(ROOT / "data")
    errors, warnings = validate(db)
    if errors:
        print("\n".join(errors)); print("validation failed; assets not built"); sys.exit(1)
    ports, kb = build(db)
    iana = iana_rows()
    kb["meta"] = {"verified": max(r["verified_date"] for r in db["ports"]),
                  "attack_version": db["sources"][[s["source_id"] for s in db["sources"]].index(f"SRC-MITRE-{db['mitre_techniques'][0]['id']}")]["document_type"],
                  "iana_fetched": (ROOT / "data/raw/iana/FETCHED_AT").read_text().strip(), "detailed": len(ports), "iana": len(iana),
                  "data_version": DATA_VERSION, "cve_fetched": (ROOT / "data/raw/cve/FETCHED_AT").read_text().strip(),
                  "kev_catalog": json.loads((ROOT / "data/raw/kev/kev_subset.json").read_text(encoding="utf-8"))["catalogVersion"]}
    for out in (ROOT / "dist", ROOT / "app/assets/data"):
        out.mkdir(parents=True, exist_ok=True)
        for name, data in [("ports", ports), ("kb", kb), ("iana", iana)]:
            (out / f"{name}.json").write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    (ROOT / "docs/VALIDATION_REPORT.md").write_text(report(db, ports, iana, errors, warnings) + quality_section(db), encoding="utf-8")
    cat = json.loads((ROOT / "data/raw/mitre/attack_catalog.json").read_text(encoding="utf-8"))
    (ROOT / "docs/MITRE_VALIDATION_REPORT.md").write_text(reports.mitre_report(db, cat), encoding="utf-8")
    (ROOT / "docs/CVE_VALIDATION_REPORT.md").write_text(reports.cve_report(db), encoding="utf-8")
    print(f"assets: ports {len(ports)} / iana {len(iana)} / techniques {len(kb['techniques'])} / dets {len(kb['dets'])}")
