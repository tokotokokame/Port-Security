#!/usr/bin/env python3
"""Generate data/schemas/*.schema.json (JSON Schema 2020-12) and docs/DATA_SCHEMA_SPEC.md from one definition.

Usage: python3 tools/make_schemas.py   (CI checks the outputs are committed)
Each field: (name, schema, required?, description). additionalProperties=false catches typos and stray fields.
"""
import json
from pathlib import Path

ROOT = Path(__file__).parent.parent
S = lambda **k: {"type": "string", **k}
ARR = lambda item, **k: {"type": "array", "items": item, **k}
DATE = S(pattern=r"^\d{4}-\d{2}-\d{2}$")
NDATE = {"anyOf": [DATE, {"type": "null"}]}
TRANSPORT = {"enum": ["TCP", "UDP", "SCTP", "DCCP"]}
PORT = {"type": "integer", "minimum": 0, "maximum": 65535}
PORT_T = {"type": "array", "prefixItems": [PORT, TRANSPORT], "minItems": 2, "maxItems": 2}
TECH = S(pattern=r"^T\d{4}(\.\d{3})?$")
SRC = S(pattern=r"^SRC-[A-Z0-9-]+$")
ATK, LOG = S(pattern=r"^ATK-[A-Z0-9-]+$"), S(pattern=r"^LOG-[A-Z0-9-]+$")
CERT = {"enum": ["確認済み", "一部確認", "未確認"]}
TEXT = S()
U = lambda item: ARR(item, uniqueItems=True)

COMMON = [("source_ids", ARR(SRC, minItems=1, uniqueItems=True), True, "根拠資料 ID（sources.source_id）"),
          ("verified_date", DATE, True, "最終確認日（YYYY-MM-DD）"),
          ("certainty", CERT, True, "確度。確認済みには再検証済みの脅威系出典が必要"),
          ("unconfirmed_notes", TEXT, True, "未確認事項。確認済み以外では必須（空不可）")]

EVIDENCE = {"type": "object", "additionalProperties": False, "required": ["source_id", "technique", "kind", "examples", "keyword"],
            "properties": {"source_id": SRC, "technique": {"anyOf": [TECH, {"type": "null"}]},
                           "kind": {"enum": ["技術説明", "手順例", "公式文書", "ATT&CK検知戦略", "政府勧告"]},
                           "examples": ARR(S()), "keyword": S(minLength=1)}}
BASIS = {"type": "object", "additionalProperties": False, "required": ["technique", "relation", "via", "source_type"],
         "properties": {"technique": TECH, "relation": {"enum": ["direct", "generic", "inferred", "unverified"]},
                        "via": ARR(S(minLength=1)), "note": S(),
                        "source_type": {"enum": ["stix", "document", "curation"]}}}  # stix=ATT&CK 公式の記述 / document=他の一次資料 / curation=アプリ内の関連付け
EVAL = {"anyOf": [
    {"type": "object", "additionalProperties": False, "required": ["category", "basis"], "properties": {"category": S(), "basis": S()}},
    {"type": "object", "additionalProperties": False, "required": ["external_exposure", "authentication", "encryption", "known_vulnerabilities"],
     "properties": {k: S() for k in ["external_exposure", "authentication", "encryption", "known_vulnerabilities"]}}]}
LOGSRC = {"type": "object", "additionalProperties": False, "required": ["channel", "event_code", "description"],
          "properties": {"channel": S(minLength=1), "event_code": {"type": ["integer", "null"]}, "description": S()}}
ANALYTIC = {"type": "object", "additionalProperties": False,
            "required": ["id", "platforms", "description", "log_sources", "monitored_ports", "port_basis", "transport_basis",
                         "service_names", "log_investigation_ids"],
            "properties": {"id": S(pattern=r"^AN\d{4}$"), "platforms": ARR(S()), "description": S(),
                           "log_sources": ARR({"type": "object", "additionalProperties": False, "required": ["name", "channel"],
                                               "properties": {"name": {"type": ["string", "null"]}, "channel": {"type": ["string", "null"]}}}),
                           "monitored_ports": ARR(PORT_T), "port_basis": {"enum": ["official", "inferred", "none"]},
                           "transport_basis": {"enum": ["stated", "service_default", "none"]},
                           "service_names": ARR(S()), "log_investigation_ids": ARR(LOG),
                           "log_links": ARR({"type": "object", "additionalProperties": False, "required": ["log_id", "basis"],
                                             "properties": {"log_id": LOG, "basis": {"enum": ["det0118_analytic", "platform_generic"]}}})}}
AFFECTED = {"type": "object", "additionalProperties": False, "required": ["vendor", "product", "versions"],
            "properties": {"vendor": S(minLength=1), "product": S(minLength=1), "versions": ARR(S(minLength=1), minItems=1),
                           "fixed": ARR(S()), "platforms": ARR(S())}}
CVSS = {"type": "object", "additionalProperties": False, "required": ["version", "score", "vector", "source"],
        "properties": {"version": {"enum": ["2.0", "3.0", "3.1", "4.0"]}, "score": {"type": "number", "minimum": 0, "maximum": 10},
                       "severity": S(), "vector": S(pattern=r"^(CVSS:\d\.\d/)?AV:"), "source": S(minLength=1)}}

SCOPES = ["attack_technique", "detection", "threat_advisory", "threat_guidance", "log_format", "service", "port_assignment",
          "protocol_assignment", "reference", "vulnerability", "vendor_security", "tool_documentation", "technical_documentation",
          "government_guidance", "research_report", "attack_framework", "vulnerability_database"]
VIA = ["original_document", "official_api", "official_stix", "official_repository", "search_result", "not_verified"]
VLOG = {"type": "object", "additionalProperties": False,
        "required": ["vendor", "product", "firmware_versions", "log_type", "log_subtype", "log_id", "message", "fields", "cli_commands",
                     "source_ids", "verification_status", "notes"],
        "properties": {"vendor": S(minLength=1), "product": S(minLength=1), "firmware_versions": ARR(S(minLength=1), minItems=1),
                       "log_type": S(minLength=1), "log_subtype": S(), "log_id": S(), "message": S(), "fields": ARR(S(minLength=1)),
                       "cli_commands": ARR(S(minLength=1)), "source_ids": ARR(SRC, minItems=1, uniqueItems=True), "verification_status": CERT,
                       "notes": S()}}
SRISK = {"type": "object", "additionalProperties": False, "required": ["level", "factors", "reason", "source_ids", "status"],
         "properties": {"level": {"enum": ["Critical", "High", "Medium", "未評価"]},
                        "factors": ARR({"enum": ["known_exploited", "attack_documented", "government_guidance", "vendor_security_warning"]}, uniqueItems=True),
                        "reason": S(minLength=1), "source_ids": ARR(SRC, uniqueItems=True), "status": CERT}}
EXPO_CODES = {"enum": ["internet", "untrusted_network", "internal_only", "management_network_only", "firewall_restricted", "auth_access_control"]}
EXPO = {"type": "object", "additionalProperties": False, "required": ["assumed", "raises", "lowers", "notes"],
        "properties": {"assumed": EXPO_CODES, "raises": ARR(EXPO_CODES, uniqueItems=True), "lowers": ARR(EXPO_CODES, uniqueItems=True), "notes": S()}}
REVIEW = {"type": "object", "additionalProperties": False, "required": ["date", "previous_level", "result", "evidence"],
          "properties": {"date": DATE, "previous_level": {"enum": ["Critical", "High", "Medium", "Low"]}, "result": S(minLength=1),
                         "reason": S(minLength=1), "evidence": ARR({"type": "object", "additionalProperties": False, "required": ["source_id", "note"],
                                                                   "properties": {"source_id": SRC, "note": S(minLength=1)}})}}

FILES = {
    "ports": ("詳細付きポート（1 レコード = 番号 + 通信方式）", "id", S(pattern=r"^PORT-\d{5}-(TCP|UDP|SCTP|DCCP)$"), [
        ("port_number", PORT, True, "ポート番号"), ("transport_protocol", TRANSPORT, True, "通信方式"),
        ("protocol_number", {"enum": [6, 17, 132, 33]}, True, "通信方式の IP プロトコル番号（TCP=6, UDP=17, SCTP=132, DCCP=33）"),
        ("protocol_id", S(pattern=r"^PROTO-[A-Z0-9]+$"), True, "protocols.id"),
        ("service_name", S(minLength=1), True, "IANA 登録名。未登録は '(未登録)'"), ("formal_name", TEXT, True, "正式名・慣用名"),
        ("iana_description", TEXT, True, "IANA 台帳の Description"), ("category", S(pattern=r"^[A-Z0-9]+$"), True, "区分（WEB, AUTH など）"),
        ("purpose", TEXT, True, "用途"), ("technical_description", TEXT, True, "技術説明"), ("normal_usage_examples", TEXT, True, "正常利用例"),
        ("malicious_exploitation_cases", TEXT, True, "悪用例"), ("suspicious_traffic_features", TEXT, True, "不審な通信の特徴"),
        ("investigation_checkpoints", TEXT, True, "調査観点"), ("recommended_defenses", TEXT, True, "対策"),
        ("attack_pattern_ids", U(ATK), True, "攻撃手法 ID"), ("technique_ids", U(TECH), True, "ATT&CK 技術 ID（technique_basis に関連区分）"),
        ("technique_basis", ARR(BASIS), True, "技術ごとの関連区分と経路"),
        ("service_id", {"anyOf": [S(pattern=r"^SRV-[A-Z0-9-]+$"), {"type": "null"}]}, True, "services.id"),
        ("risk_id", S(pattern=r"^RISK-\d{5}-(TCP|UDP|SCTP|DCCP)$"), True, "port_risks.id"),
        ("evidence", ARR(EVIDENCE), False, "ポート固有の根拠。確認済みでは必須")] + COMMON),
    "port_risks": ("ポートのリスク評価", "id", S(pattern=r"^RISK-\d{5}-(TCP|UDP|SCTP|DCCP)$"), [
        ("port_number", PORT, True, "ポート番号"), ("transport_protocol", TRANSPORT, True, "通信方式"),
        ("service_name", S(minLength=1), True, "IANA 登録名"), ("risk_level", {"enum": ["Critical", "High", "Medium", "Low"]}, True, "リスク"),
        ("reason_targeted", TEXT, True, "狙われる理由"), ("evaluation_factors", EVAL, True, "評価要素（v3 形式 / v5 形式）"),
        ("suspicious_indicators", TEXT, True, "不審な兆候"), ("investigation_focus", TEXT, True, "調査の焦点"),
        ("mitigation_controls", TEXT, True, "対策"), ("technique_ids", U(TECH), True, "ATT&CK 技術 ID"),
        ("review", REVIEW, False, "v1.2 の High 再検証の結果と根拠"),
        ("service_risk", SRISK, False, "サービス固有のリスク（一次資料で確認できた要素だけで判定。docs/RISK_RUBRIC.md）"),
        ("exposure_condition", EXPO, False, "露出条件。risk_level が前提とする露出と、上げる・下げる条件")] + COMMON),
    "services": ("サービス（プロトコル）", "id", S(pattern=r"^SRV-[A-Z0-9-]+$"), [
        ("service_name", S(minLength=1), True, "サービス名"), ("formal_name", TEXT, True, "正式名"),
        ("ports", ARR(PORT_T, minItems=1, uniqueItems=True), True, "(番号, 通信方式)。参照元ポートと一致"),
        ("port_number", PORT, False, "非推奨（v3 互換）。ports を使う"), ("transport_protocol", S(), False, "非推奨（v3 互換の文字列）"),
        ("protocol_number", {"type": "integer"}, False, "非推奨（v3 互換）"), ("purpose", TEXT, True, "用途"),
        ("technical_description", TEXT, True, "技術説明"), ("normal_usage_examples", TEXT, True, "正常利用例"),
        ("malicious_exploitation_cases", TEXT, True, "悪用例"), ("suspicious_traffic_features", TEXT, True, "不審な通信の特徴"),
        ("investigation_checkpoints", TEXT, True, "調査観点"), ("recommended_defenses", TEXT, True, "対策"),
        ("attack_pattern_ids", U(ATK), True, "攻撃手法 ID"), ("technique_ids", U(TECH), True, "ATT&CK 技術 ID")] + COMMON),
    "protocols": ("IP 上のプロトコル（IP プロトコル番号）", "id", S(pattern=r"^PROTO-[A-Z0-9]+$"), [
        ("ip_protocol_number", {"type": "integer", "minimum": 0, "maximum": 255}, True, "IANA Protocol Numbers の番号"),
        ("protocol_number", {"type": "integer", "minimum": 0, "maximum": 255}, True, "非推奨（ip_protocol_number と同値）"),
        ("service_name", S(minLength=1), True, "IANA のキーワード（小文字）"), ("formal_name", TEXT, True, "正式名"),
        ("layer", {"enum": ["L3", "L4"]}, True, "階層"), ("has_port_numbers", {"type": "boolean"}, True, "ポート番号を持つ通信方式か"),
        ("transport_protocol", S(), True, "非推奨（階層の説明文。layer を使う）"), ("purpose", TEXT, True, "用途"),
        ("technical_description", TEXT, True, "技術説明"), ("normal_usage_examples", TEXT, True, "正常利用例"),
        ("malicious_exploitation_cases", TEXT, True, "悪用例"), ("suspicious_traffic_features", TEXT, True, "不審な通信の特徴"),
        ("investigation_checkpoints", TEXT, True, "調査観点"), ("recommended_defenses", TEXT, True, "対策"),
        ("attack_pattern_ids", U(ATK), True, "攻撃手法 ID"), ("technique_ids", U(TECH), True, "ATT&CK 技術 ID")] + COMMON),
    "attack_patterns": ("攻撃手法", "id", ATK, [
        ("attack_name", S(minLength=1), True, "名称"), ("category", S(), True, "区分"), ("description", TEXT, True, "概要"),
        ("attack_features", TEXT, True, "特徴"), ("detection_methods", S(minLength=1), True, "検知方法"),
        ("recommended_defenses", TEXT, True, "対策"), ("technique_ids", U(TECH), True, "ATT&CK 技術 ID"),
        ("log_investigation_ids", U(LOG), True, "ログ調査 ID"),
        ("port_relation", {"enum": ["generic", "service_specific"]}, False, "ポートとの関係（generic=どの公開サービスにも当てはまる）"),
        ("attack_mapping_status", CERT, False, "ATT&CK 技術への対応付けの確認状態（公式 STIX との照合）"),
        ("content_verification_status", CERT, False, "説明・特徴・検知・対策の本文の確認状態"),
        ("content_source_ids", ARR(SRC, uniqueItems=True), False, "本文の根拠資料 ID")] + COMMON),
    "tools": ("攻撃ツール（検知の痕跡のみ）", "id", S(pattern=r"^TOOL-[A-Z0-9-]+$"), [
        ("name", S(minLength=1), True, "名称"), ("category", S(), True, "区分"),
        ("mitre_software_id", {"anyOf": [S(pattern=r"^S\d{4}$"), {"type": "null"}]}, True, "ATT&CK Software ID"),
        ("summary", S(minLength=1), True, "概要"), ("ports", ARR(PORT_T, uniqueItems=True), True, "主なポート (番号, 通信方式)"),
        ("artifacts", ARR(S(minLength=1)), True, "検知に使う痕跡"), ("detection", ARR(S(minLength=1)), True, "検知方法"),
        ("attack_pattern_ids", U(ATK), True, "攻撃手法 ID"), ("technique_ids", U(TECH), True, "追加の ATT&CK 技術 ID"),
        ("log_investigation_ids", U(LOG), True, "ログ調査 ID")] + COMMON),
    "log_investigation": ("ログ調査の基盤", "id", LOG, [
        ("platform", S(minLength=1), True, "基盤"), ("log_sources", ARR(LOGSRC, minItems=1), True, "ログ源（チャネル・イベント ID）"),
        ("common_fields", ARR(S()), True, "共通フィールド"), ("vendor_specific_fields", ARR(S()), True, "製品固有フィールド"),
        ("detection_analytics", TEXT, True, "検知ロジック"), ("investigation_procedure", S(minLength=1), True, "調査手順"),
        ("analytics_ids", ARR(S(pattern=r"^AN\d{4}$")), True, "対応する ATT&CK analytic"),
        ("port_scope", {"enum": ["analytics", "any", "platform", "listed"]}, True,
         "ポートとの対応方法（analytics=DET0118 の analytic 専用 / platform=プラットフォーム共通・ポート固有でない / any=境界機器 / listed=公式文書がポートを明示）"),
        ("ports", ARR(PORT_T), True, "port_scope=listed のときの (番号, 通信方式)"),
        ("vendor_logs", ARR(VLOG), False, "ベンダー機器のログ定義（版・種別・ID・フィールド・CLI ごとに出典を持つ）")] + COMMON),
    "mitre_techniques": ("ATT&CK 技術（公式 STIX から生成）", "id", S(pattern=r"^T\d{4}$"), [
        ("name", S(minLength=1), True, "名称"), ("tactics", ARR(S(), minItems=1), True, "戦術"), ("version", S(), True, "版"),
        ("created_date", DATE, True, "作成日"), ("last_modified", DATE, True, "更新日"),
        ("detection_strategy_ids", ARR(S(pattern=r"^DET\d{4}$")), True, "検知戦略 ID"),
        ("subtechniques", ARR({"type": "object", "additionalProperties": False, "required": ["id", "name", "detection_strategy_ids"],
                               "properties": {"id": S(pattern=r"^T\d{4}\.\d{3}$"), "name": S(minLength=1),
                                              "detection_strategy_ids": ARR(S(pattern=r"^DET\d{4}$"))}}), True, "サブ技術"),
        ("url", S(pattern=r"^https://attack\.mitre\.org/"), True, "公式ページ")] + COMMON),
    "detection_strategies": ("ATT&CK 検知戦略（公式 STIX から生成）", "id", S(pattern=r"^DET\d{4}$"), [
        ("name", S(minLength=1), True, "名称"), ("technique_ids", U(TECH), True, "対象技術"), ("version", S(), True, "版"),
        ("created_date", DATE, True, "作成日"), ("last_modified", DATE, True, "更新日"), ("analytics", ARR(ANALYTIC), True, "analytic"),
        ("url", S(pattern=r"^https://attack\.mitre\.org/"), True, "公式ページ"),
        ("source_ids", ARR(SRC, uniqueItems=True), True, "根拠資料 ID"), ("verified_date", DATE, True, "確認日"),
        ("certainty", CERT, True, "確度"), ("unconfirmed_notes", TEXT, True, "未確認事項")]),
    "mitre_software": ("ATT&CK Software（公式 STIX から生成）", "id", S(pattern=r"^S\d{4}$"), [
        ("name", S(minLength=1), True, "名称"), ("type", {"enum": ["malware", "tool"]}, True, "種別"), ("description", TEXT, True, "説明"),
        ("technique_ids", U(TECH), True, "uses 関係の技術"), ("url", S(pattern=r"^https://attack\.mitre\.org/"), True, "公式ページ")] + COMMON),
    "sources": ("根拠資料", "source_id", SRC, [
        ("title", S(minLength=1), True, "資料名"), ("publisher", S(), True, "発行者"), ("url", S(pattern=r"^https://"), True, "URL（https のみ）"),
        ("document_type", S(minLength=1), True, "資料種別"), ("applicable_data", S(), True, "適用対象"),
        ("publication_date", NDATE, True, "公開日"), ("last_updated", NDATE, True, "更新日"), ("access_date", DATE, True, "確認日"),
        ("verification_status", CERT, True, "内容の確認状態"), ("notes", TEXT, True, "確認した内容"),
        ("scope", ARR({"enum": SCOPES}, minItems=1, uniqueItems=True),
         True, "根拠として使える範囲"),
        ("reverified_v4", {"type": "boolean"}, True, "内容を再確認済みか（確認済みでは true 必須）"),
        ("verified_via", {"enum": VIA}, False, "確認方法。search_result は原文確認として扱わない"),
        ("verified_url", S(minLength=1), False, "実際に確認した原文の所在（URL または data/raw のパス）"),
        ("verified_date", DATE, False, "確認方法を記録した日"), ("verified_by", {"enum": ["manual_review", "automated_import"]}, False, "確認者"),
        ("verified_notes", S(), False, "確認した範囲。URL が存在するだけでは主張の根拠にならない"),
        ("usage_status", {"enum": ["使用中", "未使用・将来利用予定", "未使用・再確認待ち", "廃止"]}, False, "参照状況"),
        ("usage_notes", S(minLength=1), False, "未使用の理由"),
        ("merged_into", SRC, False, "統合先の出典 ID（ID は互換のため残す）")]),
    "vulnerabilities": ("CVE（製品・バージョン経由。ポートに直接紐付けない）", "id", S(pattern=r"^CVE-\d{4}-\d{4,7}$"), [
        ("title", S(minLength=1), True, "CVE レコードの題名"), ("description", S(minLength=1), True, "CNA の説明（英語原文の要約）"),
        ("affected", ARR(AFFECTED, minItems=1), True, "影響製品・バージョン（CVE レコードの affected）"),
        ("cvss", ARR(CVSS), True, "CVSS（提供元を明記）"), ("published", DATE, True, "公開日"), ("updated", DATE, True, "更新日"),
        ("kev", {"type": "object", "additionalProperties": False, "required": ["listed"],
                 "properties": {"listed": {"type": "boolean"}, "date_added": DATE, "ransomware": S()}}, True, "CISA KEV 掲載状況"),
        ("service_ids", U(S(pattern=r"^SRV-[A-Z0-9-]+$")), False, "関連サービス"),
        ("risk_ids", U(S(pattern=r"^RISK-\d{5}-(TCP|UDP|SCTP|DCCP)$")), True, "本文（リスク評価または対応ポート）で言及しているリスク評価。ポートとの関係は製品・構成に依存"),
        ("condition", S(minLength=1), True, "該当条件（製品・バージョン・構成）"),
        ("references", ARR(S(pattern=r"^https://"), minItems=1), True, "参照 URL"), ("raw", S(pattern=r"^data/raw/"), True, "取込元の一次データ")] + COMMON),
}


def schema(name):
    title, key, idpat, fields = FILES[name]
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": f"port-security/{name}.schema.json", "title": title,
            "type": "array", "items": {"type": "object", "additionalProperties": False,
                                       "required": [key] + [f for f, _, r, _ in fields if r],
                                       "properties": {key: idpat, **{f: {**s, "description": d} for f, s, _, d in fields}}}}


def spec():
    L = ["# DATA_SCHEMA_SPEC — データスキーマ仕様（自動生成: tools/make_schemas.py）", "",
         "スキーマ本体は `data/schemas/<file>.schema.json`（JSON Schema 2020-12）。CI で全レコードを検査する（Q-SCHEMA）。",
         "未定義のフィールドは追加できない（`additionalProperties: false`）。ID 体系は変更しない。", "",
         "## 検証状態の対応（計画書の設計例との対応）", "", "| 設計例 | 本データ |", "|---|---|",
         "| verification.status | `certainty`（確認済み / 一部確認 / 未確認） |", "| verification.verified_at | `verified_date` |",
         "| evidence[].source_id / claim | `evidence[].source_id` / `evidence[].keyword` |",
         "| evidence[].scope | 出典側の `sources.scope` |", "| evidence[].verification_status | 出典側の `sources.verification_status` |",
         "| unverified_items | `unconfirmed_notes` |", "| データ更新日・変更履歴 | `docs/DATA_CHANGELOG.md` と git 履歴 |", ""]
    for name, (title, key, idpat, fields) in FILES.items():
        L += [f"## {name}.json — {title}", "", "| フィールド | 必須 | 型・制約 | 説明 |", "|---|---|---|---|",
              f"| `{key}` | ○ | `{idpat.get('pattern')}` | ID |"]
        for f, s, r, d in fields:
            t = s.get("enum") or s.get("pattern") or s.get("type") or ("anyOf" if "anyOf" in s else "")
            L.append(f"| `{f}` | {'○' if r else '—'} | `{json.dumps(t, ensure_ascii=False) if isinstance(t, list) else t}` | {d} |")
        L.append("")
    return "\n".join(L)


if __name__ == "__main__":
    out = ROOT / "data/schemas"; out.mkdir(parents=True, exist_ok=True)
    for name in FILES:
        (out / f"{name}.schema.json").write_text(json.dumps(schema(name), ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    (ROOT / "docs/DATA_SCHEMA_SPEC.md").write_text(spec(), encoding="utf-8")
    print(f"schemas: {len(FILES)}")
