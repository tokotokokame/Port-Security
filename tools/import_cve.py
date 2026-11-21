#!/usr/bin/env python3
"""Build data/vulnerabilities.json from data/raw/cve + data/raw/kev (no network) and register the sources.

Usage: python3 tools/import_cve.py
Copied verbatim from the official records: title, description, affected products/versions, CVSS (with its provider),
published/updated dates, KEV listing. Curated in tools/cve_catalog.py: which risk mentions it and the condition.
"""
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from cve_catalog import CVES

ROOT = Path(__file__).parent.parent
DATA = ROOT / "data"


def versions(a):
    """Affected version strings and fixed versions from a CVE 5.x 'affected' entry. None when nothing is affected."""
    vs, fixed = [], []
    for v in a.get("versions", []):
        if v.get("status") == "affected":
            rng = f" < {v['lessThan']}" if v.get("lessThan") not in (None, "*") else f" ≤ {v['lessThanOrEqual']}" if v.get("lessThanOrEqual") else ""
            vs.append(f"{v['version']}{rng}".strip())
            if v.get("lessThan") not in (None, "*"): fixed.append(v["lessThan"])
        elif v.get("status") == "unaffected" and v.get("lessThan") == "*":
            fixed.append(v["version"])
    if not vs and a.get("defaultStatus") == "affected": vs = ["修正版より前の全バージョン（defaultStatus=affected）"]
    return (vs, fixed) if vs else None


def affected(cna):
    rows = {}
    for a in cna["affected"]:
        got = versions(a)
        if not got: continue
        vendor = a.get("vendor") if a.get("vendor") not in (None, "n/a") else (a.get("collectionURL") or "（CNA 記載なし）")
        product = a.get("product") or a.get("packageName") or "（CNA 記載なし）"
        r = rows.setdefault((vendor, product), {"vendor": vendor, "product": product, "versions": [], "fixed": [], "platforms": []})
        for k, vals in (("versions", got[0]), ("fixed", got[1]), ("platforms", a.get("platforms", []))):
            r[k] += [x for x in vals if x not in r[k]]
    return list(rows.values())


def cvss(rec):
    out = []
    for src in [rec["containers"]["cna"]] + rec["containers"].get("adp", []):
        who = src.get("providerMetadata", {}).get("shortName", "?")
        for m in src.get("metrics", []):
            for k, v in m.items():
                if k.startswith("cvssV") and isinstance(v, dict):
                    out.append({"version": v["version"], "score": v["baseScore"], "severity": v.get("baseSeverity", ""),
                                "vector": v["vectorString"], "source": who})
    return out


def build():
    kev = json.loads((DATA / "raw/kev/kev_subset.json").read_text(encoding="utf-8"))
    kv = {v["cveID"]: v for v in kev["vulnerabilities"]}
    vulns, sources = [], []
    fetched = (DATA / "raw/cve/FETCHED_AT").read_text().strip()
    for cid, cur in sorted(CVES.items()):
        rec = json.loads((DATA / f"raw/cve/{cid}.json").read_text(encoding="utf-8"))
        cna, meta = rec["containers"]["cna"], rec["cveMetadata"]
        desc = next(d["value"] for d in cna["descriptions"] if d["lang"].startswith("en"))
        k = kv.get(cid)
        vulns.append({
            "id": cid, "title": cna.get("title") or desc.split(".")[0][:120], "description": desc[:600],
            "affected": affected(cna), "cvss": cvss(rec), "published": meta["datePublished"][:10], "updated": meta["dateUpdated"][:10],
            "kev": {"listed": True, "date_added": k["dateAdded"], "ransomware": k["knownRansomwareCampaignUse"]} if k else {"listed": False},
            "service_ids": cur["service_ids"], "risk_ids": cur["risk_ids"], "condition": cur["condition"],
            "references": [f"https://www.cve.org/CVERecord?id={cid}"] + [r["url"] for r in cna.get("references", [])[:3] if r["url"].startswith("https://")],
            "raw": f"data/raw/cve/{cid}.json",
            "source_ids": [f"SRC-CVE-{cid[4:]}"] + (["SRC-CISA-KEV"] if k else []) + cur["source_ids"],
            "verified_date": fetched, "certainty": "確認済み",
            "unconfirmed_notes": cur["notes"]})
        sources.append({"source_id": f"SRC-CVE-{cid[4:]}", "title": f"{cid} (CVE Record)", "publisher": "CVE Program",
                        "url": f"https://www.cve.org/CVERecord?id={cid}", "document_type": "Vulnerability Record",
                        "applicable_data": "影響製品・バージョン・CVSS・公開日", "publication_date": meta["datePublished"][:10],
                        "last_updated": meta["dateUpdated"][:10], "access_date": fetched, "verification_status": "確認済み",
                        "notes": f"CVEProject/cvelistV5 の公式 JSON を取得（{cid}.json）", "scope": ["vulnerability"], "reverified_v4": True,
                        "verified_via": f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{cid[4:8]}/{int(cid.split('-')[2]) // 1000}xxx/{cid}.json"})
    sources.append({"source_id": "SRC-CISA-KEV", "title": "Known Exploited Vulnerabilities Catalog", "publisher": "CISA",
                    "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "document_type": "Government Catalog",
                    "applicable_data": "KEV 掲載状況・追加日・ランサムウェアでの利用", "publication_date": None, "last_updated": kev["dateReleased"][:10],
                    "access_date": fetched, "verification_status": "確認済み",
                    "notes": f"cisagov/kev-data（CISA 公式の GitHub 配布）catalogVersion {kev['catalogVersion']}", "scope": ["vulnerability", "threat_advisory"],
                    "reverified_v4": True, "verified_via": kev["source"]})
    return vulns, sources


if __name__ == "__main__":
    vulns, new = build()
    (DATA / "vulnerabilities.json").write_text(json.dumps(vulns, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    src = json.loads((DATA / "sources.json").read_text(encoding="utf-8"))
    idx = {s["source_id"]: i for i, s in enumerate(src)}
    for s in new:
        if s["source_id"] in idx: src[idx[s["source_id"]]] = s
        else: src.append(s)
    (DATA / "sources.json").write_text(json.dumps(src, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"vulnerabilities {len(vulns)} / sources +{len(new)}")
