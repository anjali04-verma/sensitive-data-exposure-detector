 🔗 **Live Demo:** https://sensitive-data-exposure-detector--datashield.streamlit.app/
\# Sensitive Data Exposure Detection



Detects sensitive data (passwords, card numbers, Basic auth, PAN, e-mail, API keys)

sent over \*\*unencrypted protocols\*\* (HTTP, FTP, etc.), masks every finding, and flags

server misconfigurations. Related to OWASP A02:2021 Cryptographic Failures.



> \*\*For authorised, defensive use only.\*\* Run it only in a lab or on networks you own

> or have written permission to monitor. Use fake test data only.



\## Features

\- Live packet capture with Scapy (Npcap on Windows)

\- Regex rules plus Luhn validation to cut false positives

\- Masking: raw secrets are never stored (`Secret123` becomes `Se\*\*\*\*\*23`)

\- 10-second deduplication

\- Severity scoring (Critical / High / Medium / Low) and SQLite storage

\- Scanner: HTTP to HTTPS redirect, HSTS, cookie Secure/HttpOnly, login form over HTTP

\- Streamlit dashboard with auto-refresh, risk score, filters and CSV export



\## Files

| File | Purpose |

|---|---|

| fake\_server.py | Intentionally plaintext HTTP and FTP test services |

| detector.py | Capture, detection, masking, dedup, storage |

| scanner.py | Server configuration checks |

| dashboard.py | Web dashboard |

| test\_detector.py | Unit tests and precision/recall check |



\## Setup

```

python -m venv venv

venv\\Scripts\\activate

pip install -r requirements.txt

```

Install \[Npcap](https://npcap.com) (WinPcap-compatible mode) for live capture.



\## Run (lab)

```

python fake\_server.py                       # service to test against

python detector.py                          # as Administrator

python scanner.py http://<server-ip>

streamlit run dashboard.py

python -m pytest test\_detector.py -v

```

`detector.py` looks for the adapter whose IP starts with `192.168.56.`

(VirtualBox host-only). Change that prefix in the file for another network.



\## Lab design

Windows Server VM (services + sensor) on a VirtualBox host-only network;

the host PC generates test traffic.



\## Limitations

\- TLS traffic is not inspected; the tool flags the absence of encryption.

\- Packets are scanned individually (no TCP stream reassembly yet).

\- Accuracy numbers come from synthetic test data.



\## Docs

See `docs/` for the project report and screenshots.

