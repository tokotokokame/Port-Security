#!/usr/bin/env python3
"""Fetch the official FortiGate / NEC IX documents on a CI runner and report what they actually contain.

The report (JSON) is posted as a check run so the facts used in data/log_investigation.json can be
checked against the original pages. Vendor documents are never committed. Run: python3 tools/vendor_evidence.py out.json
"""
import html.parser, io, json, re, sys, urllib.request, zipfile
from collections import Counter

UA = {"User-Agent": "Mozilla/5.0 (port-security vendor-evidence; +https://github.com/tokotokokame/Port-Security)"}
FGT = "https://docs.fortinet.com/document/fortigate/{v}/{doc}"
V74 = ["7.4.11", "7.4.10", "7.4.9", "7.4.8", "7.4.7", "7.4.6", "7.4.0"]
V76 = ["7.6.7", "7.6.6", "7.6.5", "7.6.4", "7.6.3", "7.6.0"]
TRAFFIC_FIELDS = ["logid", "type", "subtype", "level", "vd", "eventtime", "srcip", "srcport", "srcintf", "dstip", "dstport", "dstintf",
                  "proto", "action", "policyid", "sessionid", "service", "duration", "sentbyte", "rcvdbyte", "trandisp", "transip",
                  "transport", "app", "user", "group", "vpn", "srcname", "dstname"]
GRAB = [r"Message ID: ?\d+", r"Message Description: ?\S+", r"Message Meaning: ?[^\n]{1,80}", r"Type: ?\S+", r"Category: ?\S+", r"Severity: ?\S+"]


class Text(html.parser.HTMLParser):
    def __init__(self): super().__init__(); self.out, self.skip = [], 0
    def handle_starttag(self, t, a):
        if t in ("script", "style"): self.skip += 1
        if t in ("td", "th", "tr", "p", "li", "br", "div", "h1", "h2", "h3"): self.out.append("\n")
    def handle_endtag(self, t):
        if t in ("script", "style"): self.skip -= 1
    def handle_data(self, d):
        if not self.skip: self.out.append(d)


def text(raw):
    p = Text(); p.feed(raw.decode("utf-8", "replace")); return re.sub(r"\n\s*\n+", "\n", "".join(p.out))


def get(url, binary=False):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60) as r:
        return r.read() if binary else r.read(), r.geturl()


def first(urls):
    errs = []
    for u in urls:
        try:
            raw, final = get(u); return u, final, text(raw), errs
        except Exception as e: errs.append(f"{u}: {e}")
    return None, None, "", errs


def fgt(tid, doc, versions, tokens=(), grab=GRAB, snippet=1200, near=()):
    url, final, t, errs = first([FGT.format(v=v, doc=doc) for v in versions])
    words = set(re.findall(r"[A-Za-z][A-Za-z0-9_-]*", t))
    r = {"id": tid, "url": url, "final_url": final, "errors": errs[-3:], "chars": len(t),
         "grab": sorted({m for g in grab for m in re.findall(g, t)})[:30],
         "tokens_found": [x for x in tokens if x in words], "tokens_missing": [x for x in tokens if x not in words],
         "snippet": t[:snippet]}
    r["near"] = {k: [t[max(0, m.start() - 150): m.end() + 250] for m in re.finditer(k, t)][:3] for k in near}
    return r


def nec():
    out = {"id": "NEC-IX2235-ELS"}
    idx_url = "https://jpn.nec.com/univerge/ix/Download/ix2235/index.html"
    try: raw, _ = get(idx_url)
    except Exception as e: return {**out, "error": f"{idx_url}: {e}"}
    page = raw.decode("utf-8", "replace")
    links = sorted(set(re.findall(r'href="([^"]+)"', page)))
    zips = [l for l in links if l.lower().endswith(".zip")]
    out["zip_links"] = zips[:20]
    out["release_links"] = [l for l in links if "release" in l][:6]
    out["versions_on_page"] = sorted(set(re.findall(r"\b10\.\d{1,2}\.\d{1,3}\b", page)), key=lambda v: [int(x) for x in v.split(".")])[-6:]
    target = next((z for z in zips if "els" in z.lower()), None)
    if not target: return {**out, "error": "イベントログリファレンスの ZIP が見つからない"}
    zurl = urllib.parse.urljoin(idx_url, target); out["zip_url"] = zurl
    try: data, _ = get(zurl, binary=True)
    except Exception as e: return {**out, "error": f"{zurl}: {e}"}
    z = zipfile.ZipFile(io.BytesIO(data)); names = z.namelist(); out["files"] = len(names)
    docs = {n: text(z.read(n)) for n in names if n.lower().endswith((".html", ".htm"))}
    head = docs.get(next((n for n in names if n.lower().endswith("els/index.html")), ""), "")
    out["index_head"] = head[:800]
    ids = Counter(); lines = {}
    for n, t in docs.items():
        for m in re.finditer(r"\b([A-Z][A-Z0-9]{1,9})\.(\d{3})\b", t):
            ids[m.group(1)] += 1
            k = m.group(0)
            if k not in lines: lines[k] = (n, re.sub(r"\s+", " ", t[m.start(): m.start() + 260]))
    out["functions"] = ids.most_common(80)
    want = ("IP.", "FLT", "IKE", "IPSEC", "SSH", "HTTPD", "TELNET", "LOGIN", "AUTH", "NAPT", "NAT", "SYS", "GW", "MODM", "ACL", "IDS")
    out["samples"] = {k: v for k, v in sorted(lines.items()) if k.startswith(want)}
    out["samples"] = dict(list(out["samples"].items())[:120])
    kw = {}
    for word in ("フィルタ", "filter", "破棄", "discard", "deny", "reject", "ログイン", "login", "認証"):
        kw[word] = [(n, re.sub(r"\s+", " ", t[max(0, m.start() - 120): m.end() + 160])) for n, t in docs.items() for m in re.finditer(word, t)][:6]
    out["keyword_context"] = kw
    return out


def main(path):
    rep = [
        fgt("FGT-7.4-LOGREF-13", "fortios-log-message-reference/13", V74, TRAFFIC_FIELDS),
        fgt("FGT-7.6-LOGREF-13", "fortios-log-message-reference/13", V76, TRAFFIC_FIELDS),
        fgt("FGT-7.4-LOGID-DEF", "fortios-log-message-reference/656858", V74, grab=[r"[a-z-]+: ?\d+"], snippet=2500),
        fgt("FGT-7.6-LOGID-DEF", "fortios-log-message-reference/656858", V76, grab=[r"[a-z-]+: ?\d+"], snippet=2500),
        fgt("FGT-7.4-LOGREF-32001", "fortios-log-message-reference/32001", V74, ["user", "ui", "srcip", "dstip", "action", "status", "reason", "method"]),
        fgt("FGT-7.4-LOGREF-32002", "fortios-log-message-reference/32002", V74, ["user", "ui", "srcip", "dstip", "action", "status", "reason", "method"]),
        fgt("FGT-7.6-LOGREF-32002", "fortios-log-message-reference/32002", V76, ["user", "ui", "srcip", "dstip", "action", "status", "reason", "method"]),
        fgt("FGT-7.4-CLI-EXEC-LOG", "cli-reference/209945028/execute-log", V74, grab=[r"execute log [a-z-]+(?: [a-z-]+)?"], snippet=400),
        fgt("FGT-7.6-CLI-EXEC-LOG", "cli-reference/209945028/execute-log", V76, grab=[r"execute log [a-z-]+(?: [a-z-]+)?"], snippet=400),
        fgt("FGT-7.6.3-RN-SSLVPN", "fortios-release-notes/173430/ssl-vpn-tunnel-mode-replaced-with-ipsec-vpn", ["7.6.3"], grab=[], snippet=2500),
        nec(),
    ]
    blob = json.dumps(rep, ensure_ascii=False, indent=1)
    while len(blob) > 64000:  # check run の出力上限
        for r in rep:
            if r.get("snippet"): r["snippet"] = r["snippet"][: len(r["snippet"]) * 2 // 3]
            if r.get("samples"): r["samples"] = dict(list(r["samples"].items())[: max(10, len(r["samples"]) * 2 // 3)])
        blob = json.dumps(rep, ensure_ascii=False, indent=1)
    open(path, "w", encoding="utf-8").write(blob)
    print(blob[:3000])


if __name__ == "__main__":
    import urllib.parse
    main(sys.argv[1] if len(sys.argv) > 1 else "vendor_evidence.json")
