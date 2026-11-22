#!/usr/bin/env python3
"""Check `apksigner verify --print-certs` output of release APKs (F-07).

--require release: fail on a debug certificate, on APKs signed by different certificates, or on a certificate
                   that differs from the pinned fingerprint (if the pin file exists).
--require debug:   report only (PR / feature builds are never released).
Prints certificate_sha256=<hex> for the release notes.
Usage: check_signing.py --require {release,debug} [--pin FILE] CERTS...
"""
import argparse, re, sys
from pathlib import Path


def parse(text):
    if not re.search(r"^Verifies\s*$", text, re.M): return None, None, "署名の検証に失敗（Verifies がない）"
    dn = re.search(r"^Signer #1 certificate DN: (.+)$", text, re.M)
    sha = re.search(r"^Signer #1 certificate SHA-256 digest: ([0-9a-f]{64})$", text, re.M)
    if not (dn and sha): return None, None, "証明書の DN または SHA-256 を読み取れない"
    return dn.group(1).strip(), sha.group(1), None


def check(files, require, pin=None):
    errs, digests = [], {}
    for f in files:
        dn, sha, err = parse(Path(f).read_text(encoding="utf-8"))
        if err: errs.append(f"{f}: {err}"); continue
        digests[f] = sha
        if require == "release" and "CN=Android Debug" in dn: errs.append(f"{f}: デバッグ証明書で署名されている（{dn}）")
    if require == "release":
        if len(set(digests.values())) > 1: errs.append(f"APK ごとに証明書が異なる: {sorted(set(digests.values()))}")
        if pin and digests and set(digests.values()) != {pin}: errs.append(f"固定した証明書 {pin} と一致しない: {sorted(set(digests.values()))}")
    return errs, sorted(set(digests.values()))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--require", choices=["release", "debug"], required=True)
    ap.add_argument("--pin"); ap.add_argument("certs", nargs="+")
    a = ap.parse_args(argv)
    pin = None
    if a.pin and Path(a.pin).exists():
        pin = next((l.split()[0].lower() for l in Path(a.pin).read_text().splitlines() if re.match(r"^[0-9a-fA-F]{64}", l)), None)
    errs, digests = check(a.certs, a.require, pin)
    for d in digests: print(f"certificate_sha256={d}")
    print(f"signing={a.require} pinned={'yes' if pin else 'no'}")
    if a.require == "debug": print("::warning::デバッグ鍵の APK です。公開しないでください")
    for e in errs: print(f"::error::{e}")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
