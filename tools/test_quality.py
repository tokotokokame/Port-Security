"""Injected-defect tests for tools/quality.py: every quality standard must catch its own violation.
Run: python3 -m unittest discover -s tools"""
import copy, json, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import quality as Q
from validate import load_all

ROOT = Path(__file__).parent.parent
DB = load_all(ROOT / "data")
CAT = json.loads((ROOT / "data/raw/mitre/attack_catalog.json").read_text(encoding="utf-8"))


def rec(db, f, i): return next(r for r in db[f] if (r.get("id") or r.get("source_id")) == i)


class Standards(unittest.TestCase):
    def caught(self, check, mutate, code, text=""):
        db = copy.deepcopy(DB); mutate(db)
        got = [x for x in check(db) if x["code"] == code and text in x["msg"] and x["level"] == "error"]
        self.assertTrue(got, f"{code} '{text}' not detected")

    def test_clean_data_passes_everything(self):
        errs = [x for x in Q.run(copy.deepcopy(DB), ROOT, CAT) if x["level"] == "error"]
        self.assertEqual(errs, [])

    def test_json_syntax(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "bad.json").write_text("{ broken", encoding="utf-8")
            self.assertEqual(Q.load_json_files(Path(d))[0][0]["code"], "Q-JSON")

    def test_schema_extra_field(self):
        self.caught(lambda db: Q.check_schema(db, ROOT), lambda db: rec(db, "ports", "PORT-00445-TCP").update(prot="tcp"), "Q-SCHEMA")

    def test_schema_bad_enum(self):
        self.caught(lambda db: Q.check_schema(db, ROOT), lambda db: rec(db, "port_risks", "RISK-00445-TCP").update(risk_level="Severe"), "Q-SCHEMA")

    def test_duplicate_id(self):
        self.caught(Q.check_ids, lambda db: db["tools"].append(copy.deepcopy(db["tools"][0])), "Q-DUP")

    def test_unknown_attack_id(self):
        self.caught(lambda db: Q.check_attack(db, CAT), lambda db: rec(db, "ports", "PORT-00445-TCP")["technique_ids"].append("T9999"), "Q-ATTACK", "存在しない")

    def test_revoked_attack_id(self):  # T0855 is revoked in ICS v20.1
        self.caught(lambda db: Q.check_attack(db, CAT), lambda db: rec(db, "ports", "PORT-00502-TCP")["technique_ids"].append("T0855"), "Q-ATTACK", "廃止")

    def test_attack_id_in_prose(self):
        self.caught(lambda db: Q.check_attack(db, CAT), lambda db: rec(db, "attack_patterns", "ATK-BRUTE-FORCE").update(description="T1999 を使う"), "Q-ATTACK")

    def test_port_number_only_match(self):
        def m(db):
            a = next(a for d in db["detection_strategies"] if d["id"] == "DET0118" for a in d["analytics"] if a["id"] == "AN0329")
            a["monitored_ports"].append(443)
        self.caught(Q.check_transport, m, "Q-TRANSPORT", "通信方式がない")

    def test_transport_string_mix(self):
        self.caught(Q.check_transport, lambda db: rec(db, "ports", "PORT-00053-UDP").update(transport_protocol="TCP/UDP"), "Q-TRANSPORT")

    def test_protocol_number_mismatch(self):
        self.caught(Q.check_transport, lambda db: rec(db, "ports", "PORT-00053-UDP").update(protocol_number=6), "Q-TRANSPORT", "IP プロトコル番号")

    def test_ip_protocol_registry(self):
        self.caught(lambda db: Q.check_iana(db, ROOT), lambda db: rec(db, "protocols", "PROTO-GRE").update(ip_protocol_number=46), "Q-IPPROTO")

    def test_iana_name(self):
        self.caught(lambda db: Q.check_iana(db, ROOT), lambda db: rec(db, "ports", "PORT-00514-TCP").update(service_name="syslog-conn"), "Q-IANA")

    def test_source_status_undefined(self):
        self.caught(Q.check_sources, lambda db: rec(db, "sources", "SRC-NMAP").update(verification_status="未再検証"), "Q-SRC")

    def test_source_inherited_verified(self):
        self.caught(Q.check_sources, lambda db: rec(db, "sources", "SRC-NMAP").update(reverified_v4=False), "Q-SRC", "再確認記録")

    def test_source_url(self):
        self.caught(Q.check_sources, lambda db: rec(db, "sources", "SRC-NMAP").update(url="http://nmap.org/"), "Q-SRC", "URL")

    def test_verified_without_port_evidence(self):
        self.caught(Q.check_verified, lambda db: rec(db, "ports", "PORT-00445-TCP").update(evidence=[]), "Q-VERIFIED")

    def test_hidden_unconfirmed(self):
        self.caught(Q.check_verified, lambda db: rec(db, "ports", "PORT-00069-UDP").update(unconfirmed_notes=""), "Q-HIDDEN")

    def test_association_wrong_route(self):
        def m(db):
            p = rec(db, "ports", "PORT-03389-TCP")
            next(b for b in p["technique_basis"] if b["technique"] == "T1110")["via"] = ["ATK-DCSYNC"]
        self.caught(Q.check_association, m, "Q-ASSOC")

    def test_association_missing(self):
        self.caught(Q.check_association, lambda db: rec(db, "ports", "PORT-03389-TCP")["technique_ids"].append("T1046"), "Q-ASSOC")

    def test_cve_only_in_prose(self):
        self.caught(Q.check_cve, lambda db: rec(db, "port_risks", "RISK-00022-TCP").update(reason_targeted="CVE-2023-48795 の影響"), "Q-CVE")

    def test_cve_hand_edited(self):
        self.caught(Q.check_cve, lambda db: rec(db, "vulnerabilities", "CVE-2019-0708")["cvss"][0].update(score=5.0), "Q-CVE", "再生成")

    def test_cve_bound_to_port(self):
        self.caught(Q.check_cve, lambda db: rec(db, "vulnerabilities", "CVE-2019-0708").update(port_number=3389), "Q-CVE", "ポート番号")

    def test_silent_deletion(self):
        self.caught(lambda db: Q.check_count(db, ROOT), lambda db: db["tools"].pop(), "Q-COUNT")

    def test_display_fields(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "dist").mkdir()
            kb = json.loads((ROOT / "dist/kb.json").read_text(encoding="utf-8"))
            for v in kb["attacks"].values(): v.pop("notes")
            (Path(d) / "dist/kb.json").write_text(json.dumps(kb), encoding="utf-8")
            (Path(d) / "dist/ports.json").write_text((ROOT / "dist/ports.json").read_text(encoding="utf-8"), encoding="utf-8")
            self.assertTrue(any(x["code"] == "Q-HIDDEN" for x in Q.check_display(Path(d))))


if __name__ == "__main__":
    unittest.main()
