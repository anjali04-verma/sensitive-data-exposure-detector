import re, sqlite3, sys, time
from urllib.parse import urlparse
import requests

target = sys.argv[1] if len(sys.argv) > 1 else "http://192.168.56.102"
host = urlparse(target).hostname
port = urlparse(target).port or (443 if target.startswith("https") else 80)
findings = []

try:
    r = requests.get(target, allow_redirects=False, timeout=5)
except Exception as e:
    print("Cannot reach target:", e)
    sys.exit(1)

# 1. HTTP -> HTTPS redirect
if target.startswith("http://"):
    loc = r.headers.get("Location", "")
    if r.status_code not in (301, 302, 307, 308) or not loc.startswith("https://"):
        findings.append(("No HTTPS redirect", "Medium"))

# 2. HSTS
if "Strict-Transport-Security" not in r.headers:
    findings.append(("Missing HSTS header", "Low"))

# 3. Cookie flags
for c in r.raw.headers.getlist("Set-Cookie"):
    name = c.split("=")[0]
    low = c.lower()
    if "secure" not in low:
        findings.append((f"Cookie '{name}' lacks Secure flag", "Medium"))
    if "httponly" not in low:
        findings.append((f"Cookie '{name}' lacks HttpOnly flag", "Medium"))

# 4. Password form over HTTP
if target.startswith("http://") and re.search(
        r"<input[^>]+type=['\"]?password", r.text, re.I):
    findings.append(("Login form served over HTTP", "High"))

db = sqlite3.connect("events.db")
db.execute("DELETE FROM events WHERE src_ip='scanner'")
for name, sev in findings:
    db.execute("INSERT INTO events(ts,src_ip,dst_ip,protocol,port,data_type,"
               "masked_sample,severity) VALUES(?,?,?,?,?,?,?,?)",
               (time.time(), "scanner", host, "HTTP", port, name, "-", sev))
    print(f"[{sev.upper()}] {name}")
db.commit()
print(f"Scan complete: {len(findings)} issue(s) saved.")
