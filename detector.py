import re, sys, time, sqlite3
from scapy.all import sniff, conf, IP, TCP, Raw

PORTS = {80: "HTTP", 8080: "HTTP", 21: "FTP", 23: "Telnet",
         25: "SMTP", 110: "POP3", 143: "IMAP"}

def luhn(s):
    d = [int(c) for c in re.sub(r"\D", "", s)]
    if not 13 <= len(d) <= 19:
        return False
    t = 0
    for i, x in enumerate(reversed(d)):
        if i % 2 == 1:
            x *= 2
            if x > 9:
                x -= 9
        t += x
    return t % 10 == 0

def mask(v):
    v = v.strip()
    if len(v) <= 4:
        return "*" * len(v)
    return v[:2] + "*" * (len(v) - 4) + v[-2:]

RULES = [
    ("Password", r"(?i)(?:password|passwd|pwd)=([^&\s]+)", None, "Critical"),
    ("Credit card", r"\b(?:\d[ -]?){13,19}\b", luhn, "Critical"),
    ("Basic auth", r"(?i)Authorization:\s*Basic\s+(\S+)", None, "Critical"),
    ("FTP login", r"(?im)^(?:USER|PASS)\s+(\S+)", None, "Critical"),
    ("AWS key", r"\bAKIA[0-9A-Z]{16}\b", None, "High"),
    ("JWT", r"\beyJ[\w-]+\.[\w-]+\.[\w-]+\b", None, "High"),
    ("PAN", r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", None, "High"),
    ("Email", r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b", None, "Medium"),
]
RULES = [(n, re.compile(p), v, s) for n, p, v, s in RULES]

db = sqlite3.connect("events.db", check_same_thread=False)
db.execute("""CREATE TABLE IF NOT EXISTS events(
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, src_ip TEXT, dst_ip TEXT,
    protocol TEXT, port INTEGER, data_type TEXT, masked_sample TEXT,
    severity TEXT)""")

SEEN = {}
DEDUP_SECONDS = 10

def handle(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
        return
    t = pkt[TCP]
    port = t.dport if t.dport in PORTS else t.sport if t.sport in PORTS else None
    if port is None:
        return
    text = pkt[Raw].load.decode("utf-8", errors="ignore")
    for name, rx, val, sev in RULES:
        for m in rx.finditer(text):
            raw = m.group(1) if rx.groups else m.group(0)
            if val and not val(m.group(0)):
                continue
            sample = mask(raw)
            key = (pkt[IP].src, pkt[IP].dst, name, sample)
            now = time.time()
            if now - SEEN.get(key, 0) < DEDUP_SECONDS:
                continue
            SEEN[key] = now
            db.execute("INSERT INTO events(ts,src_ip,dst_ip,protocol,port,"
                       "data_type,masked_sample,severity) VALUES(?,?,?,?,?,?,?,?)",
                       (now, pkt[IP].src, pkt[IP].dst, PORTS[port],
                        port, name, sample, sev))
            db.commit()
            print(f"[{sev.upper()}] {name} over {PORTS[port]}: "
                  f"{pkt[IP].src} -> {pkt[IP].dst}  sample={sample}")

iface = None
for i in conf.ifaces.values():
    if (i.ip or "").startswith("192.168.56."):
        iface = i
        break
if iface is None:
    print("Lab adapter (192.168.56.x) not found")
    sys.exit(1)

print("Sniffing on:", iface.name, iface.ip)
sniff(iface=iface, prn=handle, store=False)
