"""Negative tests: each v3-style defect must be detected. Run: python3 -m unittest discover tools"""
import copy, sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from validate import load_all, validate

DB = load_all(Path(__file__).parent.parent / "data")


def port(db, pid): return next(p for p in db["ports"] if p["id"] == pid)


class Defects(unittest.TestCase):
    def assertCaught(self, mutate, keyword):
        db = copy.deepcopy(DB); mutate(db)
        errors, _ = validate(db)
        self.assertTrue(any(keyword in e for e in errors), f"'{keyword}' not detected: {errors[:3]}")

    def test_clean_data_passes(self):
        self.assertEqual(validate(copy.deepcopy(DB))[0], [])

    def test_det_mixed_into_techniques(self):
        self.assertCaught(lambda d: port(d, "PORT-00445-TCP")["technique_ids"].append("DET0118"), "検知戦略ID混入")

    def test_unknown_technique(self):
        self.assertCaught(lambda d: port(d, "PORT-00123-UDP")["technique_ids"].append("T9999"), "未収録")

    def test_orphan_risk(self):
        self.assertCaught(lambda d: d["ports"].remove(port(d, "PORT-00427-TCP")), "孤立")

    def test_broken_log_link(self):
        self.assertCaught(lambda d: d["attack_patterns"][0]["log_investigation_ids"].append("LOG-NONE"), "参照切れ")

    def test_overclaimed_certainty(self):
        def m(d):
            p = port(d, "PORT-00123-UDP"); p["certainty"] = "確認済み"; p["source_ids"] = ["SRC-IANA-PORT"]
        self.assertCaught(m, "根拠資料")

    def test_det0118_cited_outside_official_ports(self):
        self.assertCaught(lambda d: port(d, "PORT-00123-UDP")["source_ids"].append("SRC-MITRE-DET0118"), "公式監視ポート外")

    def test_id_mismatch(self):
        self.assertCaught(lambda d: port(d, "PORT-00022-TCP").update(port_number=23), "不一致")

    def test_one_way_log_link(self):
        self.assertCaught(lambda d: d["log_investigation"][0]["analytics_ids"].append("AN0329"), "参照がない")

    def test_tool_port_must_exist(self):
        self.assertCaught(lambda d: d["tools"][0]["ports"].append([65000, "TCP"]), "ports にない番号")

    def test_listed_log_port_must_exist(self):
        self.assertCaught(lambda d: next(l for l in d["log_investigation"] if l["id"] == "LOG-HYPERV")["ports"].append([1, "UDP"]), "ports にない番号")

    def test_evidence_source_must_be_cited(self):
        self.assertCaught(lambda d: port(d, "PORT-02375-TCP")["source_ids"].remove("SRC-DOCKER-REMOTE"), "evidence の出典")

    def test_unknown_software(self):
        self.assertCaught(lambda d: d["tools"][0].update(mitre_software_id="S9999"), "参照切れ")


if __name__ == "__main__":
    unittest.main()
