#!/usr/bin/env python3
"""Second evidence pass (2026-11-22): vendor/government documents and ATT&CK for ICS.

Usage: python3 tools/apply_evidence_docs.py [data_dir]   (run after apply_evidence.py)
Each entry was checked against the cited page's text. VERIFIED ports get 確認済み;
PARTIAL ports keep 一部確認 with a note naming what is still unsupported.
"""
import json, sys
from pathlib import Path

D = "2026-11-22"


def src(sid, title, publisher, url, dtype):
    return {"source_id": sid, "title": title, "publisher": publisher, "url": url, "document_type": dtype, "applicable_data": title,
            "publication_date": None, "last_updated": None, "access_date": D, "verification_status": "確認済み",
            "notes": "2026-11-22 再調査で本文を確認", "scope": ["threat_advisory"], "reverified_v4": True}


ICS = "https://attack.mitre.org/techniques/"
SOURCES = [
    src("SRC-DOCKER-REMOTE", "Configure remote access for Docker daemon", "Docker", "https://docs.docker.com/engine/daemon/remote-access/", "Vendor Documentation"),
    src("SRC-DOCKER-PROTECT", "Protect the Docker daemon socket", "Docker", "https://docs.docker.com/engine/security/protect-access/", "Vendor Documentation"),
    src("SRC-REDIS-SECURITY", "Redis security", "Redis", "https://redis.io/docs/latest/operate/oss_and_stack/management/security/", "Vendor Documentation"),
    src("SRC-REDIS-ANTIREZ", "A few things about Redis security", "antirez (Redis author)", "https://antirez.com/news/96", "Author Blog"),
    src("SRC-MONGODB-CHECKLIST", "Security Checklist for Self-Managed Deployments", "MongoDB", "https://www.mongodb.com/docs/manual/administration/security-checklist/", "Vendor Documentation"),
    src("SRC-K8S-KUBELET", "Kubelet authentication/authorization", "Kubernetes", "https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/", "Project Documentation"),
    src("SRC-ETCD-SECURITY", "etcd Transport security model", "etcd", "https://etcd.io/docs/v3.7/op-guide/security/", "Project Documentation"),
    src("SRC-APACHE-CVE-2023-46604", "Apache ActiveMQ CVE-2023-46604 advisory", "Apache Software Foundation", "https://activemq.apache.org/security-advisories.data/CVE-2023-46604", "Vendor Advisory"),
    src("SRC-NVD-CVE-2023-46604", "NVD CVE-2023-46604", "NIST NVD", "https://nvd.nist.gov/vuln/detail/CVE-2023-46604", "Vulnerability Database"),
    src("SRC-CISA-IPMI", "TA13-207A: Risks of Using the Intelligent Platform Management Interface (IPMI)", "CISA", "https://www.cisa.gov/ncas/alerts/TA13-207A", "Government Advisory"),
    src("SRC-CISA-TA18-106A", "TA18-106A: Russian State-Sponsored Cyber Actors Targeting Network Infrastructure Devices", "CISA", "https://us-cert.cisa.gov/ncas/alerts/TA18-106A", "Government Advisory"),
    src("SRC-CISCO-TSA18-106A", "Cisco guidance on US-CERT TA18-106A", "Cisco", "https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-20180416-tsa18-106a.html", "Vendor Advisory"),
] + [src(f"SRC-MITRE-ICS-{t.replace('.', '-')}", f"ATT&CK for ICS {t} {n}", "The MITRE Corporation", ICS + t.replace(".", "/") + "/", "MITRE ATT&CK for ICS v20.1 (STIX)")
     for t, n in [("T0836", "Modify Parameter"), ("T0869", "Standard Application Layer Protocol"), ("T0806", "Brute Force I/O"),
                  ("T0888", "Remote System Information Discovery"), ("T0846.001", "Port Scan"), ("T0883", "Internet Accessible Device"),
                  ("T0885", "Commonly Used Port"), ("T0846.002", "Broadcast Discovery"), ("T0871", "Execution through API")]]


def ev(sid, summary, kind="公式文書", technique=None, examples=()):
    return {"source_id": sid, "technique": technique, "kind": kind, "examples": list(examples), "keyword": summary}


ICS_ID = lambda t: f"SRC-MITRE-ICS-{t.replace('.', '-')}"
VERIFIED = {
    "PORT-02375-TCP": [ev("SRC-DOCKER-REMOTE", "保護せずネットワーク公開するとリモートの非 root ユーザーがホストの root 権限を得うる")],
    "PORT-02376-TCP": [ev("SRC-DOCKER-PROTECT", "鍵を持つ者はデーモンに任意の指示ができ root 権限に相当。TLS は 2376")],
    "PORT-06379-TCP": [ev("SRC-REDIS-SECURITY", "信頼された環境向けの設計。多数のインスタンスが公開 IP で放置されている"),
                       ev("SRC-REDIS-ANTIREZ", "外部公開された Redis への攻撃手法を作者が解説")],
    "PORT-10250-TCP": [ev("SRC-K8S-KUBELET", "既定で匿名要求を受け付け、既定の認可は AlwaysAllow。nodes/proxy はコマンド実行 API に到達")],
    "PORT-02379-TCP": [ev("SRC-ETCD-SECURITY", "既定では RBAC 認証も転送層の認証も無効")],
    "PORT-61616-TCP": [ev("SRC-APACHE-CVE-2023-46604", "OpenWire プロトコルのマーシャラーにリモートコード実行の脆弱性"),
                       ev("SRC-NVD-CVE-2023-46604", "ネットワーク到達でブローカーに任意コマンド実行。CISA KEV 掲載")],
    "PORT-00623-UDP": [ev("SRC-CISA-IPMI", "インターネット接続の IPMI は OS の制御を上書きできる低レベルアクセスを与える")],
    "PORT-04786-TCP": [ev("SRC-CISA-TA18-106A", "国家支援の攻撃者が SMI (4786) を含む管理プロトコルを走査・悪用"),
                       ev("SRC-CISCO-TSA18-106A", "未使用なら Smart Install を無効化するよう推奨")],
    "PORT-00502-TCP": [ev(ICS_ID("T0836"), "FrostyGoop が Modbus でパラメータを変更", "手順例", "T0836", ["S1165 FrostyGoop"]),
                       ev(ICS_ID("T0869"), "Modbus を指令通信に使用", "手順例", "T0869", ["S1165 FrostyGoop"])],
    "PORT-02404-TCP": [ev(ICS_ID("T0806"), "Industroyer が IEC 104 で I/O を総当たり操作", "手順例", "T0806", ["S0604 Industroyer"]),
                       ev(ICS_ID("T0888"), "IEC 104 で遠隔機器情報を探索", "手順例", "T0888", ["S0604 Industroyer"])],
}
PARTIAL = {
    "PORT-27017-TCP": ([ev("SRC-MONGODB-CHECKLIST", "アクセス制御の有効化とネットワーク露出の制限を推奨")],
                       "MongoDB 公式チェックリストで認証無効・露出のリスクを確認。データ削除・身代金要求の記述は未確認。"),
    "PORT-00102-TCP": ([ev(ICS_ID("T0846.001"), "Industroyer・PLC-Blaster が 102 番を走査", "手順例", "T0846.001", ["S0604 Industroyer", "S1006 PLC-Blaster"])],
                       "ATT&CK for ICS で 102 番 (S7) の探索を確認。制御プログラムの読み取り・変更の記述は未確認。"),
    "PORT-20000-TCP": ([ev(ICS_ID("T0869"), "DNP3 が攻撃に使われうる標準プロトコルとして明記", "技術説明", "T0869")],
                       "ATT&CK for ICS で DNP3 を攻撃に用いうるプロトコルとして確認。制御コマンド送信の具体例は未確認。"),
    "PORT-44818-TCP": ([ev(ICS_ID("T0883"), "インターネットから到達可能な機器の例として EtherNet/IP を明記", "技術説明", "T0883")],
                       "ATT&CK for ICS で EtherNet/IP の外部露出リスクを確認。機器制御の具体例は未確認。"),
    "PORT-47808-UDP": ([ev(ICS_ID("T0846.002"), "ブロードキャスト探索の対象として BACnet を明記", "技術説明", "T0846.002")],
                       "ATT&CK for ICS で BACnet の探索を確認。空調・照明等の制御の具体例は未確認。"),
}
FIXES = {  # factual corrections found during review
    "PORT-02375-TCP": {"technical_description": "Docker デーモンは既定で Unix ソケットのみで待ち受け、TCP は明示的な設定で有効化する。2375 は TLS なしで慣用的に使われる番号 (TLS は 2376)。"},
}


def main(data):
    data = Path(data)
    load = lambda f: json.load(open(data / f"{f}.json", encoding="utf-8"))
    ports, sources = load("ports"), load("sources")
    have = {s["source_id"] for s in sources}
    sources += [s for s in SOURCES if s["source_id"] not in have]
    for p in ports:
        pid = p["id"]
        if pid in VERIFIED: evs, cert, note = VERIFIED[pid], "確認済み", ""
        elif pid in PARTIAL: (evs, note), cert = PARTIAL[pid], "一部確認"
        else: continue
        p["evidence"] = [e for e in p.get("evidence", []) if e["source_id"] not in {x["source_id"] for x in evs}] + evs
        p["source_ids"] += [e["source_id"] for e in evs if e["source_id"] not in p["source_ids"]]
        p["certainty"], p["unconfirmed_notes"], p["verified_date"] = cert, note, D
        p.update(FIXES.get(pid, {}))
    w = lambda f, v: (data / f"{f}.json").write_text(json.dumps(v, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    w("ports", ports); w("sources", sources)
    print(f"verified {len(VERIFIED)}, partial {len(PARTIAL)}, sources +{len(SOURCES)}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).parent.parent / "data")
