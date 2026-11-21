#!/usr/bin/env python3
"""Build ATT&CK tables from the official STIX bundle (mitre-attack/attack-stix-data).

Usage: python3 tools/import_mitre.py <enterprise-attack.json> [data_dir]
Collects every technique id referenced in data/*.json and every tool's
mitre_software_id, then (re)writes mitre_techniques.json, detection_strategies.json
and mitre_software.json, and adds the matching SRC-MITRE-* sources.
"""
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mitre_catalog import DET0118, DET0118_TRANSPORT

REFS = ["ports", "services", "protocols", "attack_patterns", "port_risks", "tools"]
PLATFORM_LOGS = {"Windows": ["LOG-WIN-SECURITY"], "Linux": ["LOG-LIN-AN0328"], "macOS": ["LOG-MAC-AN0330"],
                 "ESXi": ["LOG-ESXI-AN0329"], "Network Devices": ["LOG-FORTIGATE-VENDOR", "LOG-NECIX-VENDOR"]}
DET0118_AN = {a[0]: a for a in DET0118["analytics"]}


def ext(o):
    return next((r["external_id"] for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)


def live(o): return not o.get("revoked") and not o.get("x_mitre_deprecated")


def main(stix, data):
    data = Path(data)
    objs = json.load(open(stix, encoding="utf-8"))["objects"]
    by_id = {o["id"]: o for o in objs}
    version = next(o["x_mitre_version"] for o in objs if o["type"] == "x-mitre-collection")
    techs = {ext(o): o for o in objs if o["type"] == "attack-pattern" and live(o)}
    soft = {ext(o): o for o in objs if o["type"] in ("tool", "malware") and live(o)}
    rels = [o for o in objs if o["type"] == "relationship" and live(o)]
    load = lambda f: json.load(open(data / f"{f}.json", encoding="utf-8"))
    tools = load("tools")
    wanted = {t for f in REFS for r in load(f) for t in r.get("technique_ids", [])}
    sw_ids = [t["mitre_software_id"] for t in tools if t.get("mitre_software_id")]
    missing = sorted(t for t in wanted | set(sw_ids) if t not in techs and t not in soft)
    if missing: sys.exit(f"not in ATT&CK {version}: {missing}")
    uses = {}
    for r in rels:
        if r["relationship_type"] == "uses" and r["source_ref"].startswith(("tool--", "malware--")):
            t = by_id.get(r["target_ref"])
            if t and t["type"] == "attack-pattern" and live(t): uses.setdefault(r["source_ref"], set()).add(ext(t))
    for sid in sw_ids:  # techniques a tool is documented to use are shown in the app too
        wanted |= uses.get(soft[sid]["id"], set())
    dets_of = {}
    for r in rels:
        if r["relationship_type"] == "detects":
            dets_of.setdefault(ext(by_id[r["target_ref"]]), []).append(by_id[r["source_ref"]])
    parents = sorted({t.split(".")[0] for t in wanted})
    det_rows, out_techs, needed_dets = {}, [], set()
    for pid in parents:
        p = techs[pid]
        subs = sorted(t for t in wanted if t.startswith(pid + "."))
        for t in [pid] + subs: needed_dets.update(ext(d) for d in dets_of.get(t, []) if live(d))
        out_techs.append({
            "id": pid, "name": p["name"], "tactics": [k["phase_name"] for k in p.get("kill_chain_phases", [])],
            "version": p.get("x_mitre_version"), "created_date": p["created"][:10], "last_modified": p["modified"][:10],
            "detection_strategy_ids": sorted(ext(d) for d in dets_of.get(pid, []) if live(d)),
            "subtechniques": [{"id": s, "name": techs[s]["name"],
                               "detection_strategy_ids": sorted(ext(d) for d in dets_of.get(s, []) if live(d))} for s in subs],
            "url": f"https://attack.mitre.org/techniques/{pid}/", "source_ids": [f"SRC-MITRE-{pid}"],
            "verified_date": version_date(objs), "certainty": "確認済み", "unconfirmed_notes": ""})
    for d in (o for o in objs if o["type"] == "x-mitre-detection-strategy" and live(o) and ext(o) in needed_dets):
        did = ext(d)
        targets = sorted({ext(by_id[r["target_ref"]]) for r in rels if r["relationship_type"] == "detects" and r["source_ref"] == d["id"]})
        analytics = []
        for aref in d.get("x_mitre_analytic_refs", []):
            a = by_id.get(aref)
            if not a: continue
            aid = ext(a)
            plats = a.get("x_mitre_platforms", [])
            row = {"id": aid, "platforms": plats, "description": a.get("description", ""),
                   "log_sources": [{"name": l.get("name"), "channel": l.get("channel")} for l in a.get("x_mitre_log_source_references", [])],
                   "monitored_ports": [], "port_basis": "none", "transport_basis": "none", "service_names": [],
                   "log_investigation_ids": sorted({l for pf in plats for l in PLATFORM_LOGS.get(pf, [])})}
            if did == "DET0118" and aid in DET0118_AN:
                _, _, ports, basis, svc, log = DET0118_AN[aid]
                row.update(monitored_ports=ports, port_basis=basis, transport_basis=DET0118_TRANSPORT[aid], service_names=svc,
                           log_investigation_ids=sorted(set(row["log_investigation_ids"]) | {log}))
            analytics.append(row)
        det_rows[did] = {"id": did, "name": d["name"], "technique_ids": targets, "version": d.get("x_mitre_version"),
                         "created_date": d["created"][:10], "last_modified": d["modified"][:10], "analytics": analytics,
                         "url": f"https://attack.mitre.org/detectionstrategies/{did}/",
                         "source_ids": [f"SRC-MITRE-{targets[0].split('.')[0]}"] if targets else [],
                         "verified_date": version_date(objs), "certainty": "確認済み", "unconfirmed_notes": ""}
    software = []
    for sid in sorted(set(sw_ids)):
        o = soft[sid]
        software.append({"id": sid, "name": o["name"], "type": o["type"], "description": o.get("description", ""),
                         "technique_ids": sorted(uses.get(o["id"], [])), "url": f"https://attack.mitre.org/software/{sid}/",
                         "source_ids": [f"SRC-MITRE-{sid}"], "verified_date": version_date(objs), "certainty": "確認済み",
                         "unconfirmed_notes": ""})
    sources = load("sources")
    have = {s["source_id"] for s in sources}
    def add_src(sid, title, url):
        if sid not in have:
            sources.append({"source_id": sid, "title": title, "publisher": "The MITRE Corporation", "url": url,
                            "document_type": f"MITRE ATT&CK v{version} (STIX)", "applicable_data": title,
                            "publication_date": None, "last_updated": None, "access_date": version_date(objs),
                            "verification_status": "確認済み", "notes": "公式STIXデータから取得",
                            "scope": ["attack_technique", "detection"], "reverified_v4": True})
            have.add(sid)
    for t in out_techs: add_src(f"SRC-MITRE-{t['id']}", f"{t['id']} {t['name']}", t["url"])
    for s in software: add_src(f"SRC-MITRE-{s['id']}", f"{s['id']} {s['name']}", s["url"])
    for t in tools:
        if t.get("mitre_software_id") and f"SRC-MITRE-{t['mitre_software_id']}" not in t["source_ids"]:
            t["source_ids"].insert(0, f"SRC-MITRE-{t['mitre_software_id']}")
    w = lambda f, v: (data / f"{f}.json").write_text(json.dumps(v, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    w("mitre_techniques", out_techs); w("detection_strategies", sorted(det_rows.values(), key=lambda d: d["id"]))
    w("mitre_software", software); w("sources", sources); w("tools", tools)
    print(f"ATT&CK v{version}: techniques {len(out_techs)} (+{sum(len(t['subtechniques']) for t in out_techs)} sub), "
          f"DET {len(det_rows)}, analytics {sum(len(d['analytics']) for d in det_rows.values())}, software {len(software)}")


def version_date(objs):
    return next(o["modified"][:10] for o in objs if o["type"] == "x-mitre-collection")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else Path(__file__).parent.parent / "data")
