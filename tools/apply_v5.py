#!/usr/bin/env python3
"""One-off v4 -> v5 data expansion (kept for audit). Run before tools/import_mitre.py.

Usage: python3 tools/apply_v5.py [data_dir]
"""
import csv, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from v5_catalog import ATTACKS, ATTACK_UPDATES, LOGS, SOURCES, TOOLS, V
from v5_ports import CAT, NEW, UPDATES

THREAT = {"attack_technique", "detection", "threat_advisory"}
NOTE = "ポート番号・サービス名はIANAで確認済み。攻撃・検知記述に対応する一次資料は未付与(要追加)。"
RISK_NOTE = "リスクは docs/RISK_RUBRIC.md の基準による編集判断。"
V4_CAT = {20: "FILE", 21: "FILE", 22: "REMOTE", 23: "REMOTE", 25: "MAIL", 53: "NAME", 67: "MGMT", 68: "MGMT", 69: "FILE",
          80: "WEB", 88: "AUTH", 110: "MAIL", 123: "AMP", 135: "REMOTE", 137: "NAME", 138: "NAME", 139: "FILE", 143: "MAIL",
          161: "MGMT", 162: "MGMT", 389: "AUTH", 427: "VIRT", 443: "WEB", 445: "FILE", 500: "VPN", 514: "MGMT", 587: "MAIL",
          636: "AUTH", 993: "MAIL", 995: "MAIL", 1194: "VPN", 1433: "DB", 1521: "DB", 1701: "VPN", 1723: "VPN", 3306: "DB",
          3389: "REMOTE", 4500: "VPN", 5432: "DB", 5900: "REMOTE", 5985: "REMOTE", 5986: "REMOTE", 8080: "WEB", 8443: "WEB"}
V4_RISK = {"PORT-00020-TCP": "Medium", "PORT-00021-TCP": "High", "PORT-00025-TCP": "Medium", "PORT-00053-TCP": "Medium",
           "PORT-00067-UDP": "Medium", "PORT-00068-UDP": "Low", "PORT-00069-UDP": "Medium", "PORT-00088-TCP": "High",
           "PORT-00088-UDP": "High", "PORT-00110-TCP": "Medium", "PORT-00123-UDP": "Medium", "PORT-00135-TCP": "High",
           "PORT-00137-UDP": "High", "PORT-00138-UDP": "Low", "PORT-00139-TCP": "High", "PORT-00143-TCP": "Medium",
           "PORT-00161-UDP": "High", "PORT-00162-UDP": "Low", "PORT-00389-TCP": "High", "PORT-00389-UDP": "Medium",
           "PORT-00443-UDP": "Medium", "PORT-00514-UDP": "Low", "PORT-00514-TCP": "Medium", "PORT-00587-TCP": "Medium",
           "PORT-00636-TCP": "Medium", "PORT-00993-TCP": "Low", "PORT-00995-TCP": "Low", "PORT-01194-UDP": "Medium",
           "PORT-01194-TCP": "Medium", "PORT-01433-TCP": "High", "PORT-01521-TCP": "High", "PORT-01701-UDP": "Medium",
           "PORT-01723-TCP": "High", "PORT-03306-TCP": "High", "PORT-03389-UDP": "High", "PORT-04500-UDP": "Medium",
           "PORT-00500-UDP": "Medium", "PORT-05432-TCP": "High", "PORT-05900-TCP": "High", "PORT-05986-TCP": "High",
           "PORT-08080-TCP": "Medium", "PORT-08443-TCP": "Medium"}


def pid(n, t): return f"PORT-{n:05d}-{t}"


def iana(root):
    names = {}
    for r in csv.DictReader(open(root / "raw/iana/service-names-port-numbers.csv", encoding="utf-8", newline="")):
        if r["Service Name"] and r["Port Number"].isdigit():
            names.setdefault((int(r["Port Number"]), r["Transport Protocol"].upper()), (r["Service Name"], r["Description"]))
    return names


def certify(rec, smap):
    ok = any(smap[s]["reverified_v4"] and set(smap[s]["scope"]) & THREAT for s in rec["source_ids"] if s in smap)
    rec["certainty"] = "確認済み" if ok else "一部確認"
    rec["unconfirmed_notes"] = "" if ok else (rec.get("unconfirmed_notes") or NOTE)


def risk(p, level, reason):
    label, susp, chk, deff = CAT[p["category"]]
    return {"id": p["id"].replace("PORT-", "RISK-"), "port_number": p["port_number"], "transport_protocol": p["transport_protocol"],
            "service_name": p["service_name"], "risk_level": level, "reason_targeted": reason,
            "evaluation_factors": {"category": label, "basis": "docs/RISK_RUBRIC.md"}, "suspicious_indicators": susp,
            "investigation_focus": chk, "mitigation_controls": deff, "technique_ids": list(p["technique_ids"]),
            "source_ids": list(p["source_ids"]), "verified_date": V, "certainty": "一部確認", "unconfirmed_notes": RISK_NOTE}


def main(data):
    data = Path(data)
    load = lambda f: json.load(open(data / f"{f}.json", encoding="utf-8"))
    P, R, A, L, S = (load(f) for f in ["ports", "port_risks", "attack_patterns", "log_investigation", "sources"])
    have = {s["source_id"] for s in S}
    for s in S:  # v4 sources: CISA hygiene stays advisory-only (not re-verified)
        s.setdefault("scope", ["reference"])
    S += [s for s in SOURCES if s["source_id"] not in have]
    smap = {s["source_id"]: s for s in S}
    L += [l for l in LOGS if l["id"] not in {x["id"] for x in L}]
    for l in L:
        l.setdefault("ports", [])
    for a in A:
        a["technique_ids"] = list(dict.fromkeys(a["technique_ids"] + ATTACK_UPDATES.get(a["id"], [])))
        a.setdefault("category", "")
    A += [a for a in ATTACKS if a["id"] not in {x["id"] for x in A}]
    for a in A:
        for t in a["technique_ids"]:
            sid = f"SRC-MITRE-{t.split('.')[0]}"
            if sid not in a["source_ids"]: a["source_ids"].append(sid)
    names = iana(data)
    by_id = {p["id"]: p for p in P}
    for p in P:
        p["category"] = V4_CAT.get(p["port_number"], "WEB")
        p.setdefault("iana_description", names.get((p["port_number"], p["transport_protocol"]), ("", ""))[1])
        add_a, add_t = UPDATES.get(p["id"], ([], []))
        p["attack_pattern_ids"] = list(dict.fromkeys(p["attack_pattern_ids"] + add_a))
        p["technique_ids"] = list(dict.fromkeys(p["technique_ids"] + add_t))
    for n, t, cat, label, purpose, mal, atks, techs, level, extra in NEW:
        i = pid(n, t)
        if i in by_id: sys.exit(f"duplicate {i}")
        svc, desc = names.get((n, t), ("(未登録)", ""))
        _, susp, chk, deff = CAT[cat]
        p = {"id": i, "port_number": n, "protocol_number": 6 if t == "TCP" else 17, "transport_protocol": t,
             "service_name": svc, "formal_name": label, "iana_description": desc, "category": cat, "purpose": purpose,
             "technical_description": "", "normal_usage_examples": "", "malicious_exploitation_cases": mal,
             "suspicious_traffic_features": susp, "investigation_checkpoints": chk, "recommended_defenses": deff,
             "attack_pattern_ids": atks, "technique_ids": techs, "source_ids": ["SRC-IANA-PORT"] + extra,
             "verified_date": V, "certainty": "", "unconfirmed_notes": "", "protocol_id": f"PROTO-{t}",
             "service_id": None, "risk_id": None}
        if svc == "(未登録)": p["unconfirmed_notes"] = "IANA 未登録の番号。慣用的な用途として記載。"
        P.append(p); by_id[i] = p
        R.append(risk(p, level, mal)); p["risk_id"] = R[-1]["id"]
    for p in P:
        if p["id"] in V4_RISK and not p["risk_id"]:
            R.append(risk(p, V4_RISK[p["id"]], p["malicious_exploitation_cases"])); p["risk_id"] = R[-1]["id"]
        certify(p, smap)
    P.sort(key=lambda p: (p["port_number"], p["transport_protocol"]))
    tools = [dict(t, source_ids=list(t["source_ids"])) for t in TOOLS]
    w = lambda f, v: (data / f"{f}.json").write_text(json.dumps(v, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for f, v in [("ports", P), ("port_risks", R), ("attack_patterns", A), ("log_investigation", L), ("sources", S), ("tools", tools)]:
        w(f, v)
    print(f"ports {len(P)} / risks {len(R)} / attacks {len(A)} / logs {len(L)} / tools {len(tools)} / sources {len(S)}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).parent.parent / "data")
