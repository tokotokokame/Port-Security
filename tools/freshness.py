#!/usr/bin/env python3
"""Staleness check against the official sources (network). Exit 1 when the committed primary data is out of date.

Usage: python3 tools/freshness.py [--links]
  IANA      ports / protocol numbers CSV byte-compare
  ATT&CK    latest version in attack-stix-data index.json vs data/raw/mitre/attack_catalog.json
  CVE/KEV   dateUpdated of each CVE record, KEV listing of each CVE
  --links   HTTP status of every source URL (report only: many sites reject automated requests)
"""
import json, sys, urllib.request
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from cve_catalog import CVES
from fetch_cve import CVE_URL, KEV_URL

ROOT = Path(__file__).parent.parent
IANA = {"service-names-port-numbers.csv": "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv",
        "protocol-numbers-1.csv": "https://www.iana.org/assignments/protocol-numbers/protocol-numbers-1.csv"}
ATTACK_INDEX = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"


def get(url, raw=False):
    req = urllib.request.Request(url, headers={"User-Agent": "port-security-freshness"})
    with urllib.request.urlopen(req, timeout=60) as r:
        b = r.read()
    return b if raw else json.loads(b.decode("utf-8"))


def stale():
    out = []
    for name, url in IANA.items():
        if get(url, raw=True) != (ROOT / "data/raw/iana" / name).read_bytes(): out.append(f"IANA {name} が更新されている（iana.yml を手動実行）")
    have = json.loads((ROOT / "data/raw/mitre/attack_catalog.json").read_text(encoding="utf-8"))["version"]
    latest = next(c for c in get(ATTACK_INDEX)["collections"] if c["name"] == "Enterprise ATT&CK")["versions"][0]["version"]
    if latest != have: out.append(f"ATT&CK v{latest} が公開されている（現在 v{have}。mitre_ids.py / import_mitre.py で更新）")
    kev = {v["cveID"]: v["dateAdded"] for v in get(KEV_URL)["vulnerabilities"] if v["cveID"] in CVES}
    old = {v["cveID"]: v["dateAdded"] for v in json.loads((ROOT / "data/raw/kev/kev_subset.json").read_text(encoding="utf-8"))["vulnerabilities"]}
    if kev != old: out.append(f"KEV の掲載状況が変化: {sorted(set(kev.items()) ^ set(old.items()))}")
    for cid in sorted(CVES):
        _, y, n = cid.split("-")
        now = get(CVE_URL.format(y=y, b=int(n) // 1000, id=cid))["cveMetadata"]["dateUpdated"]
        was = json.loads((ROOT / f"data/raw/cve/{cid}.json").read_text(encoding="utf-8"))["cveMetadata"]["dateUpdated"]
        if now != was: out.append(f"{cid} のレコードが更新された（{was[:10]} → {now[:10]}。fetch_cve.py → import_cve.py）")
    return out


def links():
    bad = []
    for s in json.loads((ROOT / "data/sources.json").read_text(encoding="utf-8")):
        try:
            req = urllib.request.Request(s["url"], method="GET", headers={"User-Agent": "Mozilla/5.0 port-security-linkcheck"})
            with urllib.request.urlopen(req, timeout=30) as r: code = r.status
        except Exception as e: code = getattr(e, "code", type(e).__name__)
        if code != 200: bad.append(f"{s['source_id']}: {code} {s['url']}")
    return bad


if __name__ == "__main__":
    res = stale()
    print("## 一次データの鮮度\n" + ("\n".join(f"- {x}" for x in res) or "- すべて最新"))
    if "--links" in sys.argv:
        bad = links()
        print("\n## 出典 URL（参考）\n" + ("\n".join(f"- {x}" for x in bad) or "- すべて 200"))
    sys.exit(1 if res else 0)
