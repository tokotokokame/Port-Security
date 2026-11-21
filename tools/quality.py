#!/usr/bin/env python3
"""Data-quality checks (DATA_QUALITY_STANDARD.md). Each finding: {code, level, where, msg}.

level: error = 合格基準違反 / info = 記録のみ（対象外フェーズなど）
Usage: python3 tools/quality.py [--all]   -> exit 1 if any error
"""
import json, re, sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
TRANSPORT = {"TCP": 6, "UDP": 17, "SCTP": 132, "DCCP": 33}
SRC_STATUS = {"確認済み", "一部確認", "未確認"}
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")
TECH_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")
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
    for v in db.get("vulnerabilities", []):
        w = f"vulnerabilities:{v['id']}"
        if not CVE_RE.fullmatch(v["id"]): out.append(F("Q-CVE", w, "CVE ID 形式不正"))
        if not v.get("affected"): out.append(F("Q-CVE", w, "影響製品・バージョンがない"))
        if "port_number" in v or "ports" in v: out.append(F("Q-CVE", w, "CVE をポート番号に直接紐付けている"))
    return out


def check_association(db):
    """Q-ASSOC: a port→technique link must be explained by an attack pattern, port evidence, or a service."""
    out = []
    atk = {a["id"]: set(a["technique_ids"]) for a in db["attack_patterns"]}
    for p in db["ports"]:
        via = set().union(*[atk.get(a, set()) for a in p["attack_pattern_ids"]]) if p["attack_pattern_ids"] else set()
        ev = {e["technique"] for e in p.get("evidence", []) if e.get("technique")}
        basis = {b["technique"] for b in p.get("technique_basis", [])}
        for t in p["technique_ids"]:
            parent = t.split(".")[0]
            if not ({t, parent} & (via | ev | basis) or any(x.startswith(parent + ".") for x in via)):
                out.append(F("Q-ASSOC", f"ports:{p['id']}", f"{t} の関連根拠（攻撃手法・ポート固有根拠・関連区分）がない"))
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


def check_vendor_logs(db):
    """Phase 4 対象外: FortiGate / NEC IX のフィールドは記録のみ。"""
    return [F("Q-VENDOR", f"log_investigation:{l['id']}", f"確度={l['certainty']}（Phase 4 で実機・公式マニュアル照合予定）", "info")
            for l in db["log_investigation"] if l["id"] in ("LOG-FORTIGATE-VENDOR", "LOG-NECIX-VENDOR")]


def run(db, root=ROOT, catalog=None):
    cat = catalog or json.loads((root / "data/raw/mitre/attack_catalog.json").read_text(encoding="utf-8"))
    out, _ = load_json_files(root)
    for fn in (lambda: check_schema(db, root), lambda: check_ids(db), lambda: check_attack(db, cat), lambda: check_transport(db), lambda: check_iana(db, root),
               lambda: check_sources(db), lambda: check_verified(db), lambda: check_cve(db), lambda: check_association(db),
               lambda: check_display(root), lambda: check_vendor_logs(db)):
        out += fn()
    return out


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent))
    from validate import load_all
    res = run(load_all(ROOT / "data"))
    errs = [r for r in res if r["level"] == "error"]
    for r in res if "--all" in sys.argv else errs: print(f"{r['level'].upper():5} {r['code']:<12} {r['where']}: {r['msg']}")
    print(f"quality: errors={len(errs)} info={len(res) - len(errs)} -> {'FAIL' if errs else 'PASS'}")
    sys.exit(1 if errs else 0)
