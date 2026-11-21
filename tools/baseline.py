#!/usr/bin/env python3
"""Phase 0 snapshot: docs/baseline/DATA_INVENTORY.json + BASELINE_REPORT.md (read-only on data/).

Usage: baseline.py [--v3 cyber-security-database-v3.zip]
The inventory keeps every record ID, so later phases can prove nothing was silently removed.
"""
import hashlib, json, subprocess, sys, zipfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from validate import FILES, load_all
import quality

ROOT = Path(__file__).parent.parent
ROLES = [("data/raw/", "一次データ（外部公式ソースの取得物）"), ("data/schemas/", "JSON Schema"), ("data/", "正本データ"),
         ("dist/", "生成物（アプリ用インデックス）"), ("app/assets/data/", "生成物（アプリ同梱、dist と同一）"),
         ("docs/", "文書"), ("tools/", "検証・生成スクリプト"), (".github/workflows/", "CI")]
FK = [("ports", "service_id", "services"), ("ports", "protocol_id", "protocols"), ("ports", "risk_id", "port_risks"),
      ("ports", "attack_pattern_ids", "attack_patterns"), ("ports", "technique_ids", "techniques"), ("ports", "source_ids", "sources"),
      ("port_risks", "technique_ids", "techniques"), ("attack_patterns", "technique_ids", "techniques"),
      ("attack_patterns", "log_investigation_ids", "log_investigation"), ("tools", "attack_pattern_ids", "attack_patterns"),
      ("tools", "technique_ids", "techniques"), ("tools", "log_investigation_ids", "log_investigation"),
      ("tools", "mitre_software_id", "mitre_software"), ("mitre_techniques", "detection_strategy_ids", "detection_strategies"),
      ("log_investigation", "analytics_ids", "analytics")]


def sh(cmd):
    p = subprocess.run(cmd, cwd=ROOT, shell=True, capture_output=True, text=True)
    return {"cmd": cmd, "exit": p.returncode, "tail": (p.stdout + p.stderr).strip().splitlines()[-6:]}


def git_date(path):
    return subprocess.run(["git", "log", "-1", "--format=%cs", "--", str(path)], cwd=ROOT, capture_output=True, text=True).stdout.strip() or None


def files():
    out = []
    for p in sorted(ROOT.rglob("*")):
        rel = p.relative_to(ROOT).as_posix()
        if not p.is_file() or not any(rel.startswith(k) for k, _ in ROLES): continue
        rec = {"path": rel, "role": next(r for k, r in ROLES if rel.startswith(k)), "bytes": p.stat().st_size,
               "sha256": hashlib.sha256(p.read_bytes()).hexdigest()[:16], "last_commit": git_date(rel)}
        if p.suffix == ".json":
            try:
                d = json.loads(p.read_text(encoding="utf-8")); rec["records"] = len(d) if isinstance(d, (list, dict)) else None
            except Exception: rec["records"] = "JSON構文エラー"
        out.append(rec)
    return out


def relations(db):
    ids = {f: {(r.get("id") or r.get("source_id")) for r in db[f]} for f in FILES}
    ids["techniques"] = {t["id"] for t in db["mitre_techniques"]} | {s["id"] for t in db["mitre_techniques"] for s in t["subtechniques"]}
    ids["analytics"] = {a["id"] for d in db["detection_strategies"] for a in d["analytics"]}
    out = []
    for src, field, dst in FK:
        vals = [v for r in db[src] for v in (r[field] if isinstance(r[field], list) else [r[field]]) if v is not None]
        out.append({"from": f"{src}.{field}", "to": dst, "edges": len(vals), "broken": sorted({v for v in vals if v not in ids[dst]})})
    return out


def v3_mapping(zpath, db):
    z = zipfile.ZipFile(zpath)
    names = [i.filename for i in z.infolist() if not i.is_dir()]
    groups = {}
    for n in names: groups.setdefault(hashlib.sha256(z.read(n)).hexdigest()[:12], []).append(n)
    cur = {f: {(r.get("id") or r.get("source_id")) for r in db[f]} for f in FILES}
    json_map = {"mitre_attack.json": "detection_strategies"}
    rows = []
    for n in names:
        row = {"v3_file": n, "duplicate_of": next((g[0] for g in groups.values() if n in g and g[0] != n), None)}
        if n.endswith(".json"):
            recs = json.loads(z.read(n)); tgt = json_map.get(n, n[:-5])
            old = {(r.get("id") or r.get("source_id")) for r in recs}
            if n == "mitre_attack.json":  # v3 mixed techniques and DET in one file; v4 split them
                old = {r["technique_id"] for r in recs} | {r["detection_strategy_id"] for r in recs if r["detection_strategy_id"] != "N/A"}
                tgt = "mitre_techniques+detection_strategies"; cur[tgt] = cur["mitre_techniques"] | cur["detection_strategies"]
            if n != "mitre_attack.json":
                now = {(r.get("id") or r.get("source_id")): r for r in db[tgt]}; ch = {}
                for r in recs:
                    c = now.get(r.get("id") or r.get("source_id"), {})
                    for k, v in r.items():
                        if k not in c: ch[f"{k}(削除/改名)"] = ch.get(f"{k}(削除/改名)", 0) + 1
                        elif c[k] != v: ch[k] = ch.get(k, 0) + 1
                row["changed_fields"] = dict(sorted(ch.items()))
            row.update(current=" + ".join(f"data/{x}.json" for x in tgt.split("+")), v3_records=len(recs), kept=len(old & cur[tgt]), missing=sorted(old - cur[tgt]),
                       added=len(cur[tgt] - old))
        else:
            row["current"] = "docs/（v4 で再構成。自動生成または DATA_DICTIONARY / DATA_UPDATE_GUIDE へ統合）"
        rows.append(row)
    return {"zip": Path(zpath).name, "files": len(names), "unique_contents": len(groups), "rows": rows}


def main():
    db = load_all(ROOT / "data")
    before = sh("git status --porcelain -- data dist app/assets/data docs/VALIDATION_REPORT.md")
    checks = [sh("python3 tools/validate.py data"), sh("python3 -m unittest discover -s tools"), sh("python3 tools/build_index.py"),
              sh("git diff --stat -- dist app/assets/data docs/VALIDATION_REPORT.md")]
    q = quality.run(load_all(ROOT / "data"))
    inv = {"generated": "Phase 0 baseline", "git_head": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip(),
           "record_counts": {f: len(db[f]) for f in FILES},
           "ids": {f: sorted((r.get("id") or r.get("source_id")) for r in db[f]) for f in FILES},
           "files": files(), "relations": relations(db), "commands": [before] + checks, "quality": q}
    if "--v3" in sys.argv: inv["v3"] = v3_mapping(sys.argv[sys.argv.index("--v3") + 1], db)
    out = ROOT / "docs/baseline"; out.mkdir(parents=True, exist_ok=True)
    (out / "DATA_INVENTORY.json").write_text(json.dumps(inv, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(json.dumps({k: inv[k] for k in ("git_head", "record_counts")}, ensure_ascii=False))
    print("quality errors:", sum(1 for x in q if x["level"] == "error"))


if __name__ == "__main__":
    main()
