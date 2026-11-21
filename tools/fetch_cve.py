#!/usr/bin/env python3
"""Download the official CVE records (CVEProject/cvelistV5) and the CISA KEV entries for tools/cve_catalog.py.

Usage: python3 tools/fetch_cve.py   -> data/raw/cve/CVE-*.json, data/raw/kev/kev_subset.json
Network access is needed (GitHub raw). The KEV subset keeps catalogVersion/dateReleased for provenance.
"""
import json, sys, time, urllib.request
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from cve_catalog import CVES

ROOT = Path(__file__).parent.parent
CVE_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{y}/{b}xxx/{id}.json"
KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"


def get(url):
    with urllib.request.urlopen(url, timeout=60) as r:
        return json.loads(r.read().decode("utf-8"))


def main():
    cdir, kdir = ROOT / "data/raw/cve", ROOT / "data/raw/kev"
    cdir.mkdir(parents=True, exist_ok=True); kdir.mkdir(parents=True, exist_ok=True)
    for cid in sorted(CVES):
        _, y, n = cid.split("-")
        rec = get(CVE_URL.format(y=y, b=int(n) // 1000, id=cid))
        assert rec["cveMetadata"]["cveId"] == cid, cid
        (cdir / f"{cid}.json").write_text(json.dumps(rec, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    kev = get(KEV_URL)
    sub = {"source": KEV_URL, "catalogVersion": kev["catalogVersion"], "dateReleased": kev["dateReleased"],
           "vulnerabilities": [v for v in kev["vulnerabilities"] if v["cveID"] in CVES]}
    (kdir / "kev_subset.json").write_text(json.dumps(sub, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    (cdir / "FETCHED_AT").write_text(time.strftime("%Y-%m-%d", time.gmtime()) + "\n")
    print(f"cve {len(CVES)} / kev listed {len(sub['vulnerabilities'])} (catalog {kev['catalogVersion']})")


if __name__ == "__main__":
    main()
