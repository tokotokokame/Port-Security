#!/usr/bin/env python3
"""Compact ATT&CK ID catalog from the official STIX bundles (used for offline ID checks).

Usage: mitre_ids.py enterprise-attack-X.json ics-attack-X.json > data/raw/mitre/attack_catalog.json
Every technique/software/detection strategy keeps name, revoked, deprecated and domain, so the
validator can tell "does not exist" from "exists but revoked/deprecated".
"""
import hashlib, json, sys

KINDS = {"attack-pattern": "techniques", "malware": "software", "tool": "software",
         "x-mitre-detection-strategy": "detection_strategies", "x-mitre-analytic": "analytics"}


def ext_id(o):
    return next((r["external_id"] for r in o.get("external_references", [])
                 if r.get("source_name") in ("mitre-attack", "mitre-ics-attack") and "external_id" in r), None)


def catalog(paths):
    out = {"version": None, "bundles": [], **{k: {} for k in set(KINDS.values())}}
    for path in paths:
        raw = open(path, "rb").read()
        objs = json.loads(raw)["objects"]
        coll = next(o for o in objs if o["type"] == "x-mitre-collection")
        out["version"] = coll["x_mitre_version"]
        out["bundles"].append({"name": coll["name"], "version": coll["x_mitre_version"], "sha256": hashlib.sha256(raw).hexdigest()})
        domain = "ics" if "ICS" in coll["name"] else "enterprise"
        for o in objs:
            kind, i = KINDS.get(o["type"]), ext_id(o)
            if not kind or not i: continue
            entry = {"name": o.get("name", ""), "revoked": bool(o.get("revoked")),
                     "deprecated": bool(o.get("x_mitre_deprecated")), "domain": domain}
            prev = out[kind].get(i)
            if prev is None or (prev["revoked"] or prev["deprecated"]) and not (entry["revoked"] or entry["deprecated"]):
                out[kind][i] = entry
    for k in KINDS.values(): out[k] = dict(sorted(out[k].items()))
    return out


if __name__ == "__main__":
    json.dump(catalog(sys.argv[1:]), sys.stdout, ensure_ascii=False, indent=0, sort_keys=False)
    sys.stdout.write("\n")
