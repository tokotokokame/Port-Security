"""Tests for tools/check_signing.py. Run: python3 -m unittest discover -s tools"""
import sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import check_signing as C

OUT = "Verifies\nVerified using v2 scheme (APK Signature Scheme v2): true\nNumber of signers: 1\n" \
      "Signer #1 certificate DN: {dn}\nSigner #1 certificate SHA-256 digest: {sha}\n"
REL, DBG = "a" * 64, "b" * 64


class Signing(unittest.TestCase):
    def run_check(self, outs, require, pin=None):
        with tempfile.TemporaryDirectory() as d:
            files = []
            for i, (dn, sha) in enumerate(outs):
                f = Path(d) / f"{i}.certs"; f.write_text(OUT.format(dn=dn, sha=sha)); files.append(str(f))
            return C.check(files, require, pin)[0]

    def test_release_ok(self): self.assertEqual(self.run_check([("CN=Port Security", REL)] * 2, "release", REL), [])
    def test_release_rejects_debug(self): self.assertTrue(self.run_check([("CN=Android Debug, O=Android, C=US", DBG)], "release"))
    def test_release_rejects_mixed(self): self.assertTrue(self.run_check([("CN=Port Security", REL), ("CN=Port Security", DBG)], "release"))
    def test_release_rejects_unpinned(self): self.assertTrue(self.run_check([("CN=Port Security", DBG)], "release", REL))
    def test_debug_build_reports_only(self): self.assertEqual(self.run_check([("CN=Android Debug, O=Android, C=US", DBG)], "debug"), [])

    def test_v3_signer_format(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "x.certs"
            f.write_text("Verifies\nVerified using v3 scheme (APK Signature Scheme v3): true\n"
                         f"Signer (minSdkVersion=24, maxSdkVersion=2147483647) certificate DN: C=US, O=Android, CN=Android Debug\n"
                         f"Signer (minSdkVersion=24, maxSdkVersion=2147483647) certificate SHA-256 digest: {DBG.upper()}\n")
            errs, digests = C.check([str(f)], "release")
            self.assertEqual(digests, [DBG]); self.assertTrue(any("デバッグ" in e for e in errs))

    def test_unverified_apk(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "x.certs"; f.write_text("DOES NOT VERIFY\n")
            self.assertTrue(C.check([str(f)], "release")[0])


if __name__ == "__main__":
    unittest.main()
