#!/usr/bin/env python3
"""Security gate for the release APK, fed by `aapt2 dump xmltree/permissions`.

Usage: check_manifest.py manifest.txt perms.txt   -> exit 1 on a finding
"""
import re, sys

COMPONENTS = {"activity", "activity-alias", "service", "receiver", "provider"}
ALLOWED_EXPORTED = {"com.tokotokokame.port_security.MainActivity"}  # launcher entry point
FORBIDDEN_PERMS = {"android.permission.INTERNET", "android.permission.READ_EXTERNAL_STORAGE",
                   "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.ACCESS_FINE_LOCATION",
                   "android.permission.CAMERA", "android.permission.RECORD_AUDIO", "android.permission.READ_CONTACTS"}


def truthy(v): return v.startswith("true") or "0xffffffff" in v


def parse(text):
    """Returns (application attrs, [component dicts]) from aapt2 xmltree output."""
    app, comps, stack = {}, [], []
    for line in text.splitlines():
        m = re.match(r"(\s*)([EA]): (.*)", line)
        if not m: continue
        depth, kind, body = len(m.group(1)), m.group(2), m.group(3)
        if kind == "E":
            tag = body.split(" ")[0]
            while stack and stack[-1][0] >= depth: stack.pop()
            node = {"tag": tag}
            stack.append((depth, node))
            if tag in COMPONENTS: comps.append(node)
            elif tag == "application": app = node
        elif stack:
            a = re.match(r".*:(\w+)\(0x[0-9a-f]+\)=(.*)", body)
            if a:
                val = a.group(2)
                s = re.match(r'"([^"]*)"', val)
                stack[-1][1][a.group(1)] = s.group(1) if s else val.strip()
    return app, comps


def check(manifest, perms):
    app, comps = parse(manifest)
    findings = []
    if truthy(app.get("allowBackup", "true")): findings.append("allowBackup が無効化されていない")
    if truthy(app.get("debuggable", "false")): findings.append("debuggable=true のリリースビルド")
    if truthy(app.get("usesCleartextTraffic", "false")): findings.append("平文通信 (usesCleartextTraffic) を許可")
    used = set(re.findall(r"uses-permission: name='([^']+)'", perms))
    findings += [f"不要な権限: {p}" for p in sorted(used & FORBIDDEN_PERMS)]
    print("== uses-permission"); [print("  ", p) for p in sorted(used)]
    print("== components (exported / permission)")
    for c in comps:
        exported = truthy(c.get("exported", "false"))
        print(f"   {c['tag']:<9} {c.get('name', '?')}  exported={exported}  permission={c.get('permission', '-')}")
        if exported and c.get("name") not in ALLOWED_EXPORTED and not c.get("permission"):
            findings.append(f"保護されていない外部公開コンポーネント: {c.get('name')}")
    for f in findings: print(f"::error::{f}")
    print("RESULT:", "FAIL" if findings else "PASS")
    return findings


if __name__ == "__main__":
    sys.exit(1 if check(open(sys.argv[1]).read(), open(sys.argv[2]).read()) else 0)
