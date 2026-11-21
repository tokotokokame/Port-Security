#!/usr/bin/env python3
"""Find ATT&CK text that ties a port's service to one of its techniques.

Usage: python3 tools/evidence_attack.py <enterprise-attack.json> [out.json]
For every partially confirmed port, searches the description and the procedure
examples (relationship descriptions) of each linked technique for the service's
keyword. A hit means ATT&CK itself documents the technique being carried out
over that service, which is what the port record claims.
"""
import json, re, sys
from pathlib import Path

KW = {  # port -> regex for the service as ATT&CK writes it
    20: r"\bFTP\b", 21: r"\bFTP\b", 23: r"\bTelnet\b", 25: r"\bSMTP\b", 49: r"\bTACACS", 53: r"\bDNS\b", 67: r"\bDHCP\b", 68: r"\bDHCP\b",
    69: r"\bTFTP\b", 80: r"\bHTTP\b", 88: r"\bKerberos\b", 102: r"\bS7\b|ISO-TSAP", 110: r"\bPOP3?\b", 111: r"\brpcbind\b|\bportmap",
    123: r"\bNTP\b", 137: r"NBT-NS|NetBIOS", 138: r"NetBIOS", 139: r"NetBIOS|\bSMB\b", 143: r"\bIMAP\b", 161: r"\bSNMP\b", 162: r"\bSNMP\b",
    179: r"\bBGP\b", 389: r"\bLDAP\b|\bCLDAP\b", 443: r"\bHTTPS\b|\bTLS\b", 464: r"\bKerberos\b|kpasswd", 465: r"\bSMTP\b", 500: r"\bIKE\b|ISAKMP|IPsec",
    502: r"Modbus", 512: r"\brexec\b", 513: r"\brlogin\b", 514: r"[Ss]yslog|\brsh\b", 515: r"\bLPD\b", 548: r"\bAFP\b", 587: r"\bSMTP\b",
    593: r"RPC over HTTP", 623: r"\bIPMI\b|\bBMC\b", 631: r"\bIPP\b|\bCUPS\b", 636: r"\bLDAPS?\b", 830: r"NETCONF", 853: r"DNS over TLS|\bDoT\b",
    873: r"\brsync\b", 989: r"\bFTPS\b", 990: r"\bFTPS\b", 993: r"\bIMAP", 995: r"\bPOP3", 1080: r"\bSOCKS", 1194: r"OpenVPN", 1434: r"SQL Server|MSSQL",
    1521: r"\bOracle\b", 1701: r"\bL2TP\b", 1723: r"\bPPTP\b", 1812: r"\bRADIUS\b", 1813: r"\bRADIUS\b", 1883: r"\bMQTT\b", 1985: r"\bHSRP\b",
    2049: r"\bNFS\b", 2179: r"Hyper-V", 2375: r"Docker (API|daemon)", 2376: r"Docker (API|daemon)", 2379: r"\betcd\b", 2380: r"\betcd\b",
    2404: r"IEC[ -]104|60870", 2483: r"\bOracle\b", 2484: r"\bOracle\b", 3000: r"Grafana", 3128: r"Squid|\bHTTP proxy", 3260: r"\biSCSI\b",
    3268: r"Global Catalog|\bLDAP\b", 3269: r"Global Catalog|\bLDAPS?\b", 3283: r"Apple Remote Desktop|\bARD\b", 3343: r"[Cc]luster",
    3389: r"\bRDP\b|Remote Desktop", 3478: r"\bSTUN\b", 3702: r"WS-Discovery", 4369: r"\bEPMD\b|Erlang", 4500: r"IPsec|NAT-T", 4739: r"IPFIX",
    4786: r"Smart Install", 4840: r"OPC UA", 4899: r"Radmin", 5060: r"\bSIP\b", 5061: r"\bSIP\b", 5222: r"\bXMPP\b|Jabber", 5269: r"\bXMPP\b",
    5355: r"LLMNR", 5432: r"PostgreSQL", 5601: r"Kibana", 5671: r"\bAMQP\b|RabbitMQ", 5672: r"\bAMQP\b|RabbitMQ", 5800: r"\bVNC\b",
    5938: r"TeamViewer", 5984: r"CouchDB", 6000: r"\bX11\b|X Window", 6343: r"\bsFlow\b", 6379: r"\bRedis\b", 6443: r"Kubernetes API",
    6514: r"[Ss]yslog", 6600: r"[Ll]ive [Mm]igration", 6667: r"\bIRC\b", 7547: r"TR-069|CWMP", 8000: r"\bHTTP\b", 8008: r"\bHTTP\b",
    8080: r"\bHTTP\b|port 8080", 8081: r"\bHTTP\b", 8086: r"InfluxDB", 8088: r"\bHTTP\b", 8443: r"\bHTTPS\b|port 8443", 8883: r"\bMQTT\b",
    8888: r"\bHTTP\b|port 8888", 9000: r"\bHTTP\b", 9042: r"Cassandra", 9090: r"Prometheus", 9092: r"Kafka", 9100: r"JetDirect|port 9100",
    9200: r"Elasticsearch", 9300: r"Elasticsearch", 9389: r"Active Directory Web Services|\bADWS\b", 9418: r"\bGit\b", 9443: r"\bHTTPS\b",
    10050: r"Zabbix", 10051: r"Zabbix", 10250: r"[Kk]ubelet", 11211: r"[Mm]emcache", 18083: r"VirtualBox", 20000: r"\bDNP3\b",
    27017: r"MongoDB", 44818: r"EtherNet/IP", 47808: r"BACnet", 61616: r"ActiveMQ",
}


def ext(o):
    return next((r["external_id"] for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)


def main(stix, out=None):
    objs = json.load(open(stix, encoding="utf-8"))["objects"]
    by_id = {o["id"]: o for o in objs}
    live = lambda o: not o.get("revoked") and not o.get("x_mitre_deprecated")
    tech = {ext(o): o for o in objs if o["type"] == "attack-pattern" and live(o)}
    procs = {}
    for r in objs:
        if r["type"] == "relationship" and r["relationship_type"] == "uses" and live(r) and r.get("description"):
            t = by_id.get(r["target_ref"])
            if t and t["type"] == "attack-pattern":
                procs.setdefault(ext(t), []).append((by_id[r["source_ref"]], r["description"]))
    ports = json.load(open(Path(__file__).parent.parent / "data/ports.json", encoding="utf-8"))
    result = {}
    for p in ports:
        if p["certainty"] == "確認済み" or p["port_number"] not in KW: continue
        rx = re.compile(KW[p["port_number"]])
        hits = []
        for t in p["technique_ids"]:
            o = tech.get(t)
            if not o: continue
            m = rx.search(o.get("description", ""))
            if m: hits.append({"technique": t, "kind": "description", "by": None, "keyword": m.group(0)})
            for src, desc in procs.get(t, []):
                m = rx.search(desc)
                if m: hits.append({"technique": t, "kind": "procedure", "by": f"{ext(src)} {src['name']}", "keyword": m.group(0),
                                   "text": re.sub(r"\(Citation:[^)]*\)", "", desc).strip()[:220]})
        if hits: result[p["id"]] = hits
    print(f"ports with ATT&CK evidence: {len(result)} / {sum(1 for p in ports if p['certainty'] != '確認済み')}")
    if out: Path(out).write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    return result


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
