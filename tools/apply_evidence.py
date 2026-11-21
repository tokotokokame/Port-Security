#!/usr/bin/env python3
"""Attach reviewed evidence to partially confirmed ports (audit record of 2026-11-22 review).

Usage: python3 tools/apply_evidence.py <evidence.json from evidence_attack.py> [data_dir]
Only ports listed in VERIFIED / PARTIAL are touched. VERIFIED: the evidence supports the
port's main claim. PARTIAL: it supports part of it; the note says which part.
Generic-keyword matches (HTTP on 8000/8008/8080/8081/8088/8888/9000, HTTPS on 443/udp) were rejected.
"""
import json, sys
from pathlib import Path

VERIFIED = {"PORT-00049-TCP", "PORT-00053-UDP", "PORT-00067-UDP", "PORT-00080-TCP", "PORT-00088-TCP", "PORT-00088-UDP",
            "PORT-00123-UDP", "PORT-00137-UDP", "PORT-00139-TCP", "PORT-00161-UDP", "PORT-00443-TCP", "PORT-00993-TCP",
            "PORT-01080-TCP", "PORT-03128-TCP", "PORT-03268-TCP", "PORT-03269-TCP", "PORT-05355-UDP", "PORT-05800-TCP",
            "PORT-05938-TCP", "PORT-06667-TCP"}
PARTIAL = {
    "PORT-00021-TCP": "ATT&CK T1048 で FTP による持ち出しを確認。平文盗聴・総当たり・匿名FTPの記述は未確認。",
    "PORT-00143-TCP": "ATT&CK T1114.002 で IMAP によるメール収集を確認。平文盗聴・総当たりの記述は未確認。",
    "PORT-00389-TCP": "ATT&CK T1087.002 で LDAP による列挙を確認。Bind 盗聴・LDAP 注入の記述は未確認。",
    "PORT-00636-TCP": "ATT&CK T1087.002 で LDAP による列挙を確認。証明書検証回避による中間者攻撃の記述は未確認。",
    "PORT-02049-TCP": "ATT&CK T1135 で NFS 共有の探索を確認。誤 export 設定によるファイル取得の記述は未確認。",
    "PORT-02049-UDP": "ATT&CK T1135 で NFS 共有の探索を確認。誤 export 設定によるファイル取得の記述は未確認。",
    "PORT-02375-TCP": "ATT&CK T1613 で Docker API を使った探索を確認。コンテナ作成・ホスト乗っ取りの記述は別資料で確認中。",
    "PORT-02376-TCP": "ATT&CK T1613 で Docker API を使った探索を確認。証明書管理不備の記述は未確認。",
    "PORT-03389-UDP": "ATT&CK T1210 で RDP の脆弱性悪用を確認。UDP 経由の DoS・セッション干渉の記述は未確認。",
    "PORT-04786-TCP": "ATT&CK T1190 で Smart Install が悪用対象の管理プロトコルとして明記。認証なしの設定取得・変更の記述は別資料で確認中。",
    "PORT-06443-TCP": "ATT&CK T1613 で Kubernetes API を使った探索を確認。認証情報・匿名アクセス悪用の記述は未確認。",
    "PORT-10250-TCP": "ATT&CK T1613 で kubelet API の探索 (Hildegard) を確認。Pod 内コマンド実行の記述は未確認。",
}


def main(evidence, data):
    data = Path(data)
    ev = json.load(open(evidence, encoding="utf-8"))
    ports = json.load(open(data / "ports.json", encoding="utf-8"))
    n = 0
    for p in ports:
        pid = p["id"]
        if pid not in VERIFIED and pid not in PARTIAL: continue
        hits = ev[pid]
        techs = sorted({h["technique"] for h in hits})
        p["evidence"] = [{"source_id": f"SRC-MITRE-{t.split('.')[0]}", "technique": t,
                          "kind": "手順例" if any(h["technique"] == t and h["kind"] == "procedure" for h in hits) else "技術説明",
                          "examples": sorted({h["by"] for h in hits if h["technique"] == t and h["by"]})[:3],
                          "keyword": next(h["keyword"] for h in hits if h["technique"] == t)} for t in techs]
        for e in p["evidence"]:
            if e["source_id"] not in p["source_ids"]: p["source_ids"].append(e["source_id"])
        if pid in VERIFIED:
            p["certainty"], p["unconfirmed_notes"] = "確認済み", ""
        else:
            p["certainty"], p["unconfirmed_notes"] = "一部確認", PARTIAL[pid]
        p["verified_date"] = "2026-11-22"
        n += 1
    (data / "ports.json").write_text(json.dumps(ports, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"updated {n} ports (verified {len(VERIFIED)}, partial {len(PARTIAL)})")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else Path(__file__).parent.parent / "data")
