#!/usr/bin/env python3
"""Data-quality checks (DATA_QUALITY_STANDARD.md). Each finding: {code, level, where, msg}.

level: error = 合格基準違反 / info = 記録のみ（対象外フェーズなど）
Usage: python3 tools/quality.py [--all]   -> exit 1 if any error
"""
import json, os, re, sys, urllib.parse
from pathlib import Path

ROOT = Path(__file__).parent.parent
TRANSPORT = {"TCP": 6, "UDP": 17, "SCTP": 132, "DCCP": 33}
SRC_STATUS = {"確認済み", "一部確認", "未確認"}
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")
TECH_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")
VIA_STATUS = {"original_document": "確認済み", "official_api": "確認済み", "official_stix": "確認済み", "official_repository": "確認済み",
              "search_result": "一部確認", "not_verified": "未確認"}  # 検索結果は原文確認として扱わない
SCOPE_RULE = {"attack_technique": r"MITRE", "attack_framework": r"MITRE", "threat_advisory": r"CISA|US-CERT|JPCERT|NCSC|NSA|FBI",
              "government_guidance": r"CISA|US-CERT|JPCERT|NCSC|NSA|FBI|NISC", "tool_documentation": r"Project Documentation",
              "vulnerability_database": r"Vulnerability Database", "research_report": r"Research Report|Author Blog"}
ATTRIB = {"CISA": r"CISA|Cybersecurity and Infrastructure", "US-CERT": r"CISA|US-CERT", "Palo Alto": r"Palo Alto", "Unit 42": r"Palo Alto",
          "Mirai": r"Mirai", "JPCERT": r"JPCERT", "NSA": r"NSA", "FBI": r"FBI"}
STAT_RE = re.compile(r"\d[\d,.]*\s*(%|％|分以内|分後|時間以内|万台|万件|万 ?IP|倍|割)")
RISK_SCOPE = {"attack_technique", "detection", "threat_advisory", "government_guidance", "vulnerability", "vendor_security", "research_report"}
STAT_SCOPE = {"research_report", "government_guidance", "threat_advisory"}
NON_TEXT = {"source_ids", "content_source_ids", "evidence", "technique_basis", "review", "id"}
SKIP_TEXT = {"detection_strategies", "mitre_techniques", "mitre_software"}  # MITRE 由来の原文


def F(code, where, msg, level="error"): return {"code": code, "level": level, "where": where, "msg": msg}


def rid(r): return r.get("id") or r.get("source_id")


def load_json_files(root):
    """Q-JSON: every JSON file in the repo must parse."""
    out, data = [], {}
    for p in sorted(root.glob("**/*.json")):
        if any(x in p.parts for x in (".git", "build", ".dart_tool", "node_modules")): continue
        try: data[p] = json.loads(p.read_text(encoding="utf-8"))
        except Exception as e: out.append(F("Q-JSON", str(p.relative_to(root)), f"JSON構文エラー: {e}"))
    return out, data


def check_schema(db, root):
    """Q-SCHEMA: data/<name>.json must satisfy data/schemas/<name>.schema.json."""
    sdir = root / "data/schemas"
    if not sdir.exists(): return [F("Q-SCHEMA", "data/schemas", "JSON Schema 未整備")]
    sys.path.insert(0, str(Path(__file__).parent))
    from schema_check import check as schema
    out = []
    for name, recs in db.items():
        sp = sdir / f"{name}.schema.json"
        if not sp.exists(): out.append(F("Q-SCHEMA", name, "スキーマファイルなし")); continue
        out += [F("Q-SCHEMA", f"{name}{w}", m) for w, m in schema(json.loads(sp.read_text(encoding="utf-8")), recs)]
    return out


def check_ids(db):
    """Q-DUP: IDs unique within and across files."""
    out, seen = [], {}
    for f, recs in db.items():
        for r in recs:
            i = rid(r)
            if i in seen: out.append(F("Q-DUP", f"{f}:{i}", f"ID重複 ({seen[i]})"))
            seen[i] = f
    return out


def check_attack(db, cat):
    """Q-ATTACK: every ATT&CK ID (structured fields and our own prose) exists, is current, and names match."""
    out, T = [], cat["techniques"]
    def ok(where, i):
        e = T.get(i)
        if e is None: out.append(F("Q-ATTACK", where, f"{i} は ATT&CK v{cat['version']} に存在しない"))
        elif e["revoked"] or e["deprecated"]: out.append(F("Q-ATTACK", where, f"{i} は廃止済み(revoked/deprecated)"))
    for f, recs in db.items():
        for r in recs:
            w = f"{f}:{rid(r)}"
            for i in r.get("technique_ids", []): ok(w, i)
            for e in r.get("evidence", []):
                if e.get("technique"): ok(w + ":evidence", e["technique"])
            if f not in SKIP_TEXT and f != "sources":
                for i in set(TECH_RE.findall(json.dumps({k: v for k, v in r.items() if k != "technique_ids"}, ensure_ascii=False))): ok(w + ":本文", i)
    for t in db["mitre_techniques"]:
        for x in [t] + t["subtechniques"]:
            e = T.get(x["id"])
            if e and e["name"] != x["name"]: out.append(F("Q-ATTACK", f"mitre_techniques:{x['id']}", f"名称不一致 '{x['name']}' != '{e['name']}'"))
    for s in db["mitre_software"]:
        e = cat["software"].get(s["id"])
        if not e or e["revoked"] or e["deprecated"]: out.append(F("Q-ATTACK", f"mitre_software:{s['id']}", "存在しない/廃止済み"))
    for d in db["detection_strategies"]:
        if d["id"] not in cat["detection_strategies"]: out.append(F("Q-ATTACK", f"detection_strategies:{d['id']}", "存在しない"))
        out += [F("Q-ATTACK", f"detection_strategies:{d['id']}/{a['id']}", "analytic が存在しない") for a in d["analytics"] if a["id"] not in cat["analytics"]]
    return out


def _tp(where, tp, code="Q-TRANSPORT"):
    return [] if tp in TRANSPORT else [F(code, where, f"通信方式 '{tp}' が TCP/UDP/SCTP/DCCP のいずれでもない")]


def check_transport(db):
    """Q-TRANSPORT: TCP/UDP/SCTP never mixed; protocol numbers consistent; port matches always carry a transport."""
    out = []
    protos = {p["id"]: p for p in db["protocols"]}
    for p in db["ports"]:
        w = f"ports:{p['id']}"; tp = p["transport_protocol"]
        out += _tp(w, tp)
        if TRANSPORT.get(tp) != p.get("protocol_number"): out.append(F("Q-TRANSPORT", w, f"IP プロトコル番号 {p.get('protocol_number')} が {tp} と不一致"))
        pr = protos.get(p.get("protocol_id"))
        if pr and pr["protocol_number"] != TRANSPORT.get(tp): out.append(F("Q-TRANSPORT", w, "protocol_id が通信方式と不一致"))
    for r in db["port_risks"]: out += _tp(f"port_risks:{r['id']}", r["transport_protocol"])
    for s in db["services"]:
        w = f"services:{s['id']}"
        if "ports" in s:
            for n, tp in s["ports"]: out += _tp(w, tp)
        else: out.append(F("Q-TRANSPORT", w, f"ポートが通信方式付きで定義されていない（transport_protocol='{s.get('transport_protocol')}'）"))
    for t in db["tools"]:
        for n, tp in t["ports"]: out += _tp(f"tools:{t['id']}", tp)
    for l in db["log_investigation"]:
        for n, tp in l["ports"]: out += _tp(f"log_investigation:{l['id']}", tp)
    for d in db["detection_strategies"]:
        for a in d["analytics"]:
            for mp in a["monitored_ports"]:
                if not (isinstance(mp, list) and len(mp) == 2): out.append(F("Q-TRANSPORT", f"{d['id']}/{a['id']}", f"監視ポート {mp} に通信方式がない（番号のみで照合される）"))
                else: out += _tp(f"{d['id']}/{a['id']}", mp[1])
    for p in db["protocols"]:
        w = f"protocols:{p['id']}"
        if "ip_protocol_number" not in p or "layer" not in p:
            out.append(F("Q-IPPROTO", w, f"transport_protocol に階層の説明 '{p['transport_protocol']}' が入っている（IP プロトコル番号と通信方式の区別が曖昧）"))
        elif p["has_port_numbers"] != (p["service_name"].upper() in TRANSPORT) or TRANSPORT.get(p["service_name"].upper(), p["ip_protocol_number"]) != p["ip_protocol_number"]:
            out.append(F("Q-IPPROTO", w, "ポート番号を持つ通信方式の判定または番号が不一致"))
    return out


def iana_ports(root):
    """(port, TRANSPORT) -> {service name: description} from the official IANA CSV (ranges expanded)."""
    import csv
    out = {}
    for r in csv.DictReader(open(root / "data/raw/iana/service-names-port-numbers.csv", encoding="utf-8", newline="")):
        name, num, tp = r["Service Name"].strip(), r["Port Number"].strip(), r["Transport Protocol"].upper()
        if not name or not num or tp not in TRANSPORT: continue
        lo, _, hi = num.partition("-")
        for n in range(int(lo), int(hi or lo) + 1): out.setdefault((n, tp), {}).setdefault(name, r["Description"].strip())
    return out


def check_iana(db, root):
    """Q-IANA: service_name / iana_description are the IANA registration of (number, transport); '(未登録)' only when IANA has none.
    Q-IPPROTO: protocol numbers and keywords match the IANA Protocol Numbers registry."""
    out, reg = [], iana_ports(root)
    for p in db["ports"]:
        w, names = f"ports:{p['id']}", reg.get((p["port_number"], p["transport_protocol"]))
        if names is None:
            if p["service_name"] != "(未登録)": out.append(F("Q-IANA", w, f"IANA 未登録なのに service_name='{p['service_name']}'"))
        elif p["service_name"] not in names:
            out.append(F("Q-IANA", w, f"service_name '{p['service_name']}' が IANA 登録名 {sorted(names)} にない"))
        elif p.get("iana_description", "") != names[p["service_name"]]:
            out.append(F("Q-IANA", w, f"iana_description が IANA の記載 '{names[p['service_name']]}' と不一致"))
    pcsv = root / "data/raw/iana/protocol-numbers-1.csv"
    if not pcsv.exists(): return out + [F("Q-IPPROTO", "data/raw/iana", "IANA Protocol Numbers 台帳が未取得（iana.yml で取得）")]
    import csv
    kw = {r["Decimal"].strip(): r["Keyword"].strip().upper() for r in csv.DictReader(open(pcsv, encoding="utf-8", newline=""))}
    for p in db["protocols"]:
        n = str(p.get("ip_protocol_number", p["protocol_number"]))
        if kw.get(n) != p["service_name"].upper(): out.append(F("Q-IPPROTO", f"protocols:{p['id']}", f"IANA では {n} = {kw.get(n)}（データは {p['service_name']}）"))
    return out


def check_sources(db):
    """Q-SRC: every source has a defined verification status and an https URL."""
    out = []
    for s in db["sources"]:
        w = f"sources:{s['source_id']}"
        if s.get("verification_status") not in SRC_STATUS: out.append(F("Q-SRC", w, f"確認状態 '{s.get('verification_status')}' が未定義値"))
        if not re.fullmatch(r"https://[^\s/]+\.[^\s]+", str(s.get("url"))): out.append(F("Q-SRC", w, f"URL 不正: {s.get('url')}"))
        if s.get("reverified_v4") and s.get("verification_status") not in ("確認済み",): out.append(F("Q-SRC", w, "再検証済みなのに確認状態が確認済みでない"))
        if s.get("verification_status") == "確認済み" and not s.get("access_date"): out.append(F("Q-SRC", w, "確認済みなのに確認日(access_date)がない"))
        if s.get("verification_status") == "確認済み" and not s.get("reverified_v4"): out.append(F("Q-SRC", w, "確認済みだが内容の再確認記録がない（v3 からの継承値）"))
        via = s.get("verified_via")
        if via not in VIA_STATUS: out.append(F("Q-VIA", w, f"確認方法 verified_via='{via}' が未定義値")); continue
        if VIA_STATUS[via] != s.get("verification_status"):
            out.append(F("Q-VIA", w, f"確認方法 {via} では確認状態は {VIA_STATUS[via]}（データは {s.get('verification_status')}）"))
        if via != "not_verified" and not (s.get("verified_url") and s.get("verified_date") and s.get("verified_notes")):
            out.append(F("Q-VIA", w, "確認した原文の所在・日付・範囲（verified_url / verified_date / verified_notes）がない"))
        for sc in s.get("scope", []):
            rule = SCOPE_RULE.get(sc)
            if rule and not re.search(rule, f"{s.get('publisher')} | {s.get('document_type')}"):
                out.append(F("Q-SCOPE", w, f"scope '{sc}' が発行者・資料種別（{s.get('publisher')} / {s.get('document_type')}）と合わない"))
    return out


def _text(r): return json.dumps({k: v for k, v in r.items() if k not in NON_TEXT}, ensure_ascii=False)


def check_attribution(db):
    """Q-ATTR: 本文で組織名を挙げるなら、その組織の確認済み出典が必要。Q-STAT: 統計値には調査報告・政府資料の確認済み出典が必要。"""
    out, src = [], {s["source_id"]: s for s in db["sources"]}
    for f, recs in db.items():
        if f in SKIP_TEXT or f in ("sources", "vulnerabilities"): continue
        for r in recs:
            w, t = f"{f}:{rid(r)}", _text(r)
            ids = [s for s in r.get("source_ids", []) + r.get("content_source_ids", []) if src.get(s, {}).get("verification_status") == "確認済み"]
            for org, pub in ATTRIB.items():
                if org in t and not any(re.search(pub, src[s]["publisher"] + " " + src[s].get("verified_notes", "") + " " + src[s]["title"]) for s in ids):
                    out.append(F("Q-ATTR", w, f"本文が「{org}」に帰属させているが、確認済みの該当出典がない"))
            for m in STAT_RE.finditer(t):  # 数値が、調査報告・政府資料の確認済み出典の確認範囲（verified_notes）に記録されていること
                num = re.match(r"[\d,.]+", m.group(0)).group(0)
                if not any(set(src[s]["scope"]) & STAT_SCOPE and num in src[s].get("verified_notes", "") for s in ids):
                    out.append(F("Q-STAT", w, f"統計値「{m.group(0)}」を確認した調査報告・政府資料の出典がない"))
    return out


def check_review(db):
    """Q-REVIEW: High は再検証の根拠が必須。判定を変えたものは理由が必須。"""
    out, src = [], {s["source_id"]: s for s in db["sources"]}
    port_src = {p["risk_id"]: p["source_ids"] + [e["source_id"] for e in p.get("evidence", [])] for p in db["ports"]}
    for r in db["port_risks"]:
        w, rv = f"port_risks:{r['id']}", r.get("review")
        cand = r["source_ids"] + port_src.get(r["id"], [])
        strong = any(src.get(x, {}).get("verification_status") == "確認済み" and set(src[x]["scope"]) & RISK_SCOPE for x in cand)
        if r["risk_level"] in ("Critical", "High") and not (rv and rv["evidence"]) and not strong:
            out.append(F("Q-REVIEW", w, f"{r['risk_level']} だが攻撃・脆弱性・政府資料の確認済み根拠も再検証の根拠（review.evidence）もない"))
        if rv and rv["previous_level"] != r["risk_level"] and not rv.get("reason"): out.append(F("Q-REVIEW", w, "リスク判定を変更したが理由（review.reason）がない"))
        for e in (rv or {}).get("evidence", []):
            if e["source_id"] not in r["source_ids"]: out.append(F("Q-REVIEW", w, f"再検証の根拠 {e['source_id']} が source_ids にない"))
    return out


def check_verified(db):
    """Q-VERIFIED / Q-HIDDEN: 確認済み needs verified evidence; anything else must state what is unverified."""
    out, src = [], {s["source_id"]: s for s in db["sources"]}
    for f, recs in db.items():
        if f == "sources": continue
        for r in recs:
            w = f"{f}:{r['id']}"
            if r.get("certainty") != "確認済み":
                if not r.get("unconfirmed_notes"): out.append(F("Q-HIDDEN", w, "確認済み以外なのに未確認事項が空"))
                continue
            weak = [s for s in r["source_ids"] if src.get(s, {}).get("verification_status") != "確認済み"]
            if r["source_ids"] and len(weak) == len(r["source_ids"]): out.append(F("Q-VERIFIED", w, "確認済みだが確認済みの出典が1件もない"))
            if f == "ports" and not r.get("evidence"): out.append(F("Q-VERIFIED", w, "確認済みだがポート固有の根拠(evidence)がない"))
    return out


def check_cve(db):
    """Q-CVE: CVE mentioned in our prose must exist as a structured record (product/version), never bound to a port alone."""
    out, known = [], {v["id"] for v in db.get("vulnerabilities", [])}
    for f, recs in db.items():
        if f in SKIP_TEXT or f in ("sources", "vulnerabilities"): continue
        for r in recs:
            for c in sorted(set(CVE_RE.findall(json.dumps(r, ensure_ascii=False)))):
                if c not in known: out.append(F("Q-CVE", f"{f}:{rid(r)}", f"{c} が本文のみで、製品・影響バージョン付きの構造化データがない"))
            if "MS17-010" in json.dumps(r, ensure_ascii=False) and "CVE-2017-0144" not in json.dumps(r, ensure_ascii=False):
                out.append(F("Q-CVE", f"{f}:{rid(r)}", "MS17-010 の記載に対応 CVE がない"))
    ptext = {p["risk_id"]: json.dumps(p, ensure_ascii=False) for p in db["ports"]}
    risks = {r["id"]: json.dumps(r, ensure_ascii=False) + ptext.get(r["id"], "") for r in db["port_risks"]}  # リスク評価または対応ポートの本文
    try:
        sys.path.insert(0, str(Path(__file__).parent)); from import_cve import build
        rebuilt = {v["id"]: v for v in build()[0]}
    except FileNotFoundError as e: rebuilt = {}; out.append(F("Q-CVE", "data/raw/cve", f"一次データがない: {e}"))
    for v in db.get("vulnerabilities", []):
        w = f"vulnerabilities:{v['id']}"
        if rebuilt and rebuilt.get(v["id"]) != v: out.append(F("Q-CVE", w, "data/raw の公式レコードから再生成した内容と一致しない（手編集の疑い）"))
        for risk_id in v["risk_ids"]:
            if v["id"] not in risks.get(risk_id, ""): out.append(F("Q-CVE", w, f"{risk_id}（または対応ポート）の本文に {v['id']} の記載がない"))
        if not CVE_RE.fullmatch(v["id"]): out.append(F("Q-CVE", w, "CVE ID 形式不正"))
        if not v.get("affected"): out.append(F("Q-CVE", w, "影響製品・バージョンがない"))
        if "port_number" in v or "ports" in v: out.append(F("Q-CVE", w, "CVE をポート番号に直接紐付けている"))
    return out


def _fam(a, b): return a == b or a.split(".")[0] == b or b.split(".")[0] == a


def check_association(db):
    """Q-ASSOC: every port→technique link has exactly one technique_basis whose route is true in the data (F-10).
    direct = port evidence names the technique / generic = linked attack patterns that apply to any exposed service contain it
    inferred = linked service-specific attack patterns contain it, or the service lists it, or a note explains it / unverified = note required."""
    out = []
    atk = {a["id"]: a for a in db["attack_patterns"]}
    svc = {s["id"]: s["technique_ids"] for s in db["services"]}
    for p in db["ports"]:
        w, basis = f"ports:{p['id']}", p.get("technique_basis")
        if basis is None: out.append(F("Q-ASSOC", w, "technique_basis（関連区分）がない")); continue
        got = [b["technique"] for b in basis]
        if sorted(got) != sorted(p["technique_ids"]): out.append(F("Q-ASSOC", w, f"technique_basis {got} が technique_ids と一致しない"))
        for b in basis:
            t, rel, via = b["technique"], b["relation"], b["via"]
            pats = lambda kind: via and all(v in p["attack_pattern_ids"] and atk.get(v, {}).get("port_relation") == kind
                                           and any(_fam(t, x) for x in atk[v]["technique_ids"]) for v in via)
            ok = {"direct": lambda: via and all(any(e["source_id"] == v and e.get("technique") == t for e in p.get("evidence", [])) for v in via),
                  "generic": lambda: pats("generic"),
                  "inferred": lambda: pats("service_specific") or (via == [p["service_id"]] and any(_fam(t, x) for x in svc.get(p["service_id"], [])))
                                      or bool(b.get("note")),
                  "unverified": lambda: bool(b.get("note"))}.get(rel, lambda: False)()
            if not ok: out.append(F("Q-ASSOC", w, f"{t} の関連区分 {rel} の経路 {via} がデータと一致しない"))
            want = ("stix" if via and all(v.startswith("SRC-MITRE-") for v in via) else "document") if rel == "direct" else "curation"
            if b.get("source_type") != want: out.append(F("Q-ASSOC", w, f"{t} の根拠種別 source_type は {want}（ATT&CK 公式の記述か、アプリ内の関連付けかを区別）"))
    for a in db["attack_patterns"]:
        if "T1078.001" in a["technique_ids"] and a["id"] == "ATK-UNAUTH-SERVICE":
            out.append(F("Q-ASSOC", f"attack_patterns:{a['id']}", "認証のないサービスに Default Accounts（T1078.001）を対応付けている"))
    return out


DISPLAY = {"attacks": ("certainty", "notes", "verified"), "tools": ("certainty", "notes", "verified"),
           "logs": ("certainty", "notes", "verified")}


def check_display(root):
    """Q-HIDDEN: the app assets must carry certainty / unconfirmed notes / review date for every entity."""
    out, d = [], root / "dist"
    if not (d / "kb.json").exists(): return [F("Q-HIDDEN", "dist", "生成物がない")]
    kb, ports = json.loads((d / "kb.json").read_text(encoding="utf-8")), json.loads((d / "ports.json").read_text(encoding="utf-8"))
    for sect, keys in DISPLAY.items():
        miss = sorted({k for v in kb[sect].values() for k in keys if k not in v})
        if miss: out.append(F("Q-HIDDEN", f"kb.{sect}", f"アプリ用データに {', '.join(miss)} がない（画面に表示できない）"))
    if any(p["risk"] and "notes" not in p["risk"] for p in ports): out.append(F("Q-HIDDEN", "ports.risk", "リスク評価の未確認事項がアプリ用データにない"))
    if any("certainty" not in s for s in kb["sources"].values()): out.append(F("Q-HIDDEN", "kb.sources", "出典の確認状態(3値)がアプリ用データにない"))
    return out


def check_log_links(db):
    """Q-LOGLINK: DET0118 専用のログは DET0118 の analytic にだけ付ける。共通ログを analytic 専用として付けない（F-06）。"""
    out, scope = [], {l["id"]: l["port_scope"] for l in db["log_investigation"]}
    for d in db["detection_strategies"]:
        for a in d["analytics"]:
            w, links = f"detection_strategies:{d['id']}/{a['id']}", a.get("log_links")
            if links is None: out.append(F("Q-LOGLINK", w, "log_links（関連付けの根拠）がない")); continue
            if sorted({x["log_id"] for x in links}) != sorted(a["log_investigation_ids"]):
                out.append(F("Q-LOGLINK", w, "log_investigation_ids が log_links と一致しない"))
            for x in links:
                specific = scope.get(x["log_id"]) == "analytics"
                if x["basis"] == "det0118_analytic" and (d["id"] != "DET0118" or not specific):
                    out.append(F("Q-LOGLINK", w, f"{x['log_id']} を DET0118 の analytic 専用ログとして付けている"))
                if x["basis"] == "platform_generic" and specific:
                    out.append(F("Q-LOGLINK", w, f"DET0118 専用の {x['log_id']} をプラットフォーム共通ログとして付けている"))
    return out


LOG_CLASS = {0: "B", 1: "A", 2: "B", 3: "B'", 4: "C/D", 5: "C/D"}


def check_log_class(root):
    """Q-LOGCLASS: アプリ用データのログ分類が 5 章の定義どおりで、ポート固有ログの有無を A・B だけで判定していること（F-15）。"""
    out, d = [], root / "dist"
    if not (d / "ports.json").exists(): return [F("Q-LOGCLASS", "dist", "生成物がない")]
    kb = json.loads((d / "kb.json").read_text(encoding="utf-8"))
    generic = {i for i, l in kb["logs"].items() if l.get("scope") in ("platform", "any")}
    for p in json.loads((d / "ports.json").read_text(encoding="utf-8")):
        w = f"dist/ports:{p['id']}"
        for l in p["logs"]:
            if l.get("class") != LOG_CLASS.get(l["rank"]): out.append(F("Q-LOGCLASS", w, f"{l['id']} の分類 {l.get('class')} が順位 {l['rank']} と合わない"))
            if l.get("class") in ("A", "B") and l["id"] in generic: out.append(F("Q-LOGCLASS", w, f"共通ログ {l['id']} をポート固有（{l['class']}）として数えている"))
        has = any(l.get("class") in ("A", "B") for l in p["logs"])
        if has == ("ポート固有のログなし（A・B なし）" in p["gaps"]): out.append(F("Q-LOGCLASS", w, "ポート固有ログの有無の判定が A・B の有無と一致しない"))
    return out


def check_count(db, root):
    """Q-COUNT: an ID from the Phase 0 baseline may disappear only if DATA_CHANGELOG.md names it (no silent deletion)."""
    inv = root / "docs/baseline/DATA_INVENTORY.json"
    if not inv.exists(): return [F("Q-COUNT", "docs/baseline", "基準スナップショットがない")]
    base = json.loads(inv.read_text(encoding="utf-8"))["ids"]
    log = (root / "docs/DATA_CHANGELOG.md").read_text(encoding="utf-8")
    now = {f: {rid(r) for r in recs} for f, recs in db.items()}
    gone = [ln for ln in log.splitlines() if re.search(r"削除|改名|統合", ln)]  # ID を挙げた行が削除・改名・統合の記録であること
    return [F("Q-COUNT", f"{f}:{i}", "基準にあった ID が消えたが DATA_CHANGELOG.md に削除・改名の記録がない")
            for f, ids in base.items() for i in ids if i not in now.get(f, set()) and not any(i in ln for ln in gone)]


def _evidence(root):
    p = root / "data/raw/vendor/fortios_evidence.json"
    if not p.exists(): return {}
    return {"SRC-FTNT-" + k.replace("FGT-", "").replace(".", ""): v for k, v in json.loads(p.read_text(encoding="utf-8"))["pages"].items()}


def check_vendor_logs(db, root=ROOT):
    """Q-VENDOR: ベンダーログは版・種別・ID・フィールド・CLI ごとにページ単位の出典を持ち、確認済みの項目は取得した原文の抽出結果にあること。"""
    out, src, ev = [], {s["source_id"]: s for s in db["sources"]}, _evidence(root)
    for l in db["log_investigation"]:
        w, vl = f"log_investigation:{l['id']}", l.get("vendor_logs")
        if vl is None:
            if l["port_scope"] == "any" and l["id"].endswith("-VENDOR"): out.append(F("Q-VENDOR", w, "ベンダー機器のログに vendor_logs（版・出典付きの定義）がない"))
            continue
        ok_fields = set()
        for i, e in enumerate(vl):
            we = f"{w}/vendor_logs/{i}"
            for s in e["source_ids"]:
                x = src.get(s)
                if not x: out.append(F("Q-VENDOR", we, f"出典 {s} がない")); continue
                if urllib.parse.urlparse(x["url"]).path.strip("/") == "": out.append(F("Q-VENDOR", we, f"出典 {s} がサイトのトップページで、ページを特定していない"))
            if e["verification_status"] != "確認済み": continue
            if any(src.get(s, {}).get("verification_status") != "確認済み" for s in e["source_ids"]):
                out.append(F("Q-VENDOR", we, "確認済みだが、確認済みでない出典を含む")); continue
            pages = [ev[s] for s in e["source_ids"] if s in ev]
            have = {f for pg in pages for f in pg.get("fields", [])}; cmds = {c for pg in pages for c in pg.get("commands", [])}
            if not pages: out.append(F("Q-VENDOR", we, "確認済みだが原文の抽出結果（data/raw/vendor）に対応するページがない")); continue
            for f in e["fields"]:
                if f not in have: out.append(F("Q-VENDOR", we, f"フィールド {f} が原文のフィールド表にない"))
            for c in e["cli_commands"]:
                if not any(c.split(" <")[0] == k.split(" <")[0] for k in cmds): out.append(F("Q-VENDOR", we, f"CLI {c} が原文のコマンド一覧にない"))
            for v in e["firmware_versions"]:
                if not any(f"/{v}/" in pg["url"] for pg in pages): out.append(F("Q-VENDOR", we, f"版 {v} の資料が出典にない"))
            ok_fields |= set(e["fields"])
        for f in l["common_fields"] + l["vendor_specific_fields"]:
            if f not in ok_fields: out.append(F("Q-VENDOR", w, f"フィールド {f} が確認済みの vendor_logs にない（未確認のフィールドを一覧に残している）"))
    return out


def run(db, root=ROOT, catalog=None):
    cat = catalog or json.loads((root / "data/raw/mitre/attack_catalog.json").read_text(encoding="utf-8"))
    out, _ = load_json_files(root)
    for fn in (lambda: check_schema(db, root), lambda: check_ids(db), lambda: check_attack(db, cat), lambda: check_transport(db), lambda: check_iana(db, root),
               lambda: check_sources(db), lambda: check_verified(db), lambda: check_cve(db), lambda: check_association(db),
               lambda: check_attribution(db), lambda: check_review(db),
               lambda: check_display(root), lambda: check_count(db, root), lambda: check_log_links(db), lambda: check_log_class(root), lambda: check_vendor_logs(db, root)):
        out += fn()
    return out


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent))
    from validate import load_all
    res = run(load_all(ROOT / "data"))
    errs = [r for r in res if r["level"] == "error"]
    for r in res if "--all" in sys.argv else errs: print(f"{r['level'].upper():5} {r['code']:<12} {r['where']}: {r['msg']}")
    if os.environ.get("GITHUB_ACTIONS"):  # PR 画面に注釈として表示
        for r in errs[:50]: print(f"::error title={r['code']}::{r['where']}: {r['msg']}")
    print(f"quality: errors={len(errs)} info={len(res) - len(errs)} -> {'FAIL' if errs else 'PASS'}")
    sys.exit(1 if errs else 0)
