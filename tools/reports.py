"""Generated reports: docs/MITRE_VALIDATION_REPORT.md and docs/CVE_VALIDATION_REPORT.md (called from build_index.py)."""
import json
from collections import Counter
import quality

FOCUS = ["T1110", "T1110.001", "T1110.002", "T1110.003", "T1110.004", "T1021.001", "T1021.002", "T1021.004", "T1046", "T1210"]


def mitre_report(db, cat):
    T = cat["techniques"]
    names = {t["id"]: t["name"] for t in db["mitre_techniques"]} | {s["id"]: s["name"] for t in db["mitre_techniques"] for s in t["subtechniques"]}
    findings = quality.check_attack(db, cat)
    structured = {t for f, recs in db.items() for r in recs for t in r.get("technique_ids", [])}
    basis = [(p, b) for p in db["ports"] for b in p.get("technique_basis", [])]
    rel = Counter(b["relation"] for _, b in basis)
    L = ["# MITRE_VALIDATION_REPORT（自動生成: tools/build_index.py）", "",
         f"- 照合元: ATT&CK v{cat['version']} 公式 STIX（`data/raw/mitre/attack_catalog.json`）",
         *[f"  - {b['name']} v{b['version']} sha256 `{b['sha256'][:16]}…`" for b in cat["bundles"]],
         f"- 照合した技術 ID: 構造化フィールド {len(structured)} 個（本文中の ID も含めて検査）",
         f"- 存在しない / 廃止（revoked・deprecated）/ 名称不一致: **{len(findings)} 件**", ""]
    L += [f"- {x['where']}: {x['msg']}" for x in findings]
    L += ["## 重点確認対象", "", "| ID | 公式名 | 状態 | 本データの名称 | 紐付くポート（関連区分） |", "|---|---|---|---|---|"]
    for t in FOCUS:
        e = T.get(t)
        state = "存在しない" if not e else ("廃止" if e["revoked"] or e["deprecated"] else "有効")
        c = Counter(b["relation"] for _, b in basis if b["technique"] == t)
        L.append(f"| {t} | {e['name'] if e else '—'} | {state} | {names.get(t, '（未収録）')} | "
                 f"{', '.join(f'{k} {v}' for k, v in sorted(c.items())) or '—'} |")
    L += ["", "## ポート → 技術の関連区分", "", "ATT&CK の技術とポート番号は直接結び付けず、経路（Port → 根拠 / 攻撃手法 / サービス → Technique）を持たせる。", "",
          "| 区分 | 件数 | 意味 |", "|---|---|---|",
          f"| direct | {rel['direct']} | ポート固有の根拠（ATT&CK 手続き例・検知戦略・公式文書）が技術を名指し |",
          f"| attack_pattern | {rel['attack_pattern']} | 紐付く攻撃手法がその技術（または親・サブ技術）を含む |",
          f"| service | {rel['service']} | サービスの性質から対象になる |",
          f"| reference | {rel['reference']} | 参考情報（一次資料未付与） |", "",
          "### service / reference の内訳", "", "| ポート | 技術 | 区分 | 説明 |", "|---|---|---|---|"]
    L += [f"| {p['port_number']}/{p['transport_protocol']} | {b['technique']} | {b['relation']} | {b.get('note', '') or ', '.join(b['via'])} |"
          for p, b in basis if b["relation"] in ("service", "reference")]
    L += ["", "## DET0118 の監視ポートと通信方式の根拠", "", "| analytic | ポート | port_basis | transport_basis |", "|---|---|---|---|"]
    for d in db["detection_strategies"]:
        for a in d["analytics"]:
            if a["monitored_ports"]:
                L.append(f"| {d['id']}/{a['id']} | {' '.join(f'{n}/{t.lower()}' for n, t in a['monitored_ports'])} | {a['port_basis']} | {a['transport_basis']} |")
    L += ["", "- stated: analytic 本文に通信方式の記載あり（例: `tcp/427`） / service_default: 番号のみの記載で、サービスの標準通信方式を採用",
          "- ポートとの照合は (番号, 通信方式) の一致のみ。番号だけの一致では紐付けない。"]
    return "\n".join(L) + "\n"


def cve_report(db):
    V = db.get("vulnerabilities", [])
    findings = [x for x in quality.check_cve(db)]
    L = ["# CVE_VALIDATION_REPORT（自動生成: tools/build_index.py）", "",
         "- 取込元: CVE Program 公式レコード（CVEProject/cvelistV5）と CISA KEV（cisagov/kev-data）。`data/raw/cve/` に原文を保存",
         "- CVE はポート番号に直接紐付けない。製品・影響バージョン・構成を `condition` に明記し、リスク評価から参照する",
         f"- 収録: {len(V)} 件 / 検査の違反: **{len(findings)} 件**", ""]
    L += [f"- {x['where']}: {x['msg']}" for x in findings]
    L += ["| CVE | 製品 | 影響バージョン | 修正 | CVSS | KEV | 該当条件 |", "|---|---|---|---|---|---|---|"]
    for v in V:
        more = lambda xs, n: "; ".join(xs[:n]) + (f"（ほか {len(xs) - n} 件）" if len(xs) > n else "")
        prod = more([f"{a['vendor']} {a['product']}" for a in v["affected"]], 2)
        first = v["affected"][0]
        vers = more(first["versions"], 2)[:160]
        fixed = more(sorted({f for a in v["affected"] for f in a.get("fixed", [])}), 3) or "—"
        cv = "; ".join(f"{c['score']} (v{c['version']}, {c['source']})" for c in v["cvss"]) or "—"
        kev = f"掲載 {v['kev'].get('date_added', '')}" if v["kev"]["listed"] else "未掲載"
        L.append(f"| {v['id']} | {prod} | {vers} | {fixed} | {cv} | {kev} | {v['condition']} |")
    return "\n".join(L) + "\n"
