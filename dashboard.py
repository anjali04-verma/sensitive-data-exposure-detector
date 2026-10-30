import sqlite3
import pandas as pd
import streamlit as st

st.set_page_config(page_title="Sensitive Data Exposure Monitor",
                   page_icon="🛡️", layout="wide")

st.markdown("""<style>
.block-container{padding-top:1.4rem}
.card{border-radius:12px;padding:14px 18px;background:#161b26;border:1px solid #2a3142}
.card h4{margin:0;font-size:13px;color:#9aa4b8;font-weight:500}
.card p{margin:4px 0 0 0;font-size:32px;font-weight:700}
.banner{border-radius:12px;padding:14px 18px;margin-bottom:14px;font-weight:600;font-size:17px}
.barrow{display:flex;align-items:center;margin:8px 0;font-size:14px}
.barlabel{width:80px}
.bartrack{flex:1;background:#232a3a;border-radius:6px;height:20px;margin:0 10px}
.barfill{height:20px;border-radius:6px}
</style>""", unsafe_allow_html=True)

COLORS = {"Critical": "#ef4444", "High": "#f97316", "Medium": "#eab308", "Low": "#38bdf8"}
ICON = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵"}
WEIGHT = {"Critical": 10, "High": 5, "Medium": 2, "Low": 1}
ADVICE = {
    "HTTP": "Serve the site over HTTPS, redirect HTTP to HTTPS, and add an HSTS header.",
    "FTP": "Replace FTP with SFTP or FTPS.",
    "Telnet": "Replace Telnet with SSH.",
    "SMTP": "Require STARTTLS or use SMTPS.",
    "POP3": "Use POP3S (port 995).",
    "IMAP": "Use IMAPS (port 993).",
}
COLS = ["id", "ts", "src_ip", "dst_ip", "protocol", "port",
        "data_type", "masked_sample", "severity"]

def load():
    try:
        con = sqlite3.connect("events.db")
        df = pd.read_sql("SELECT * FROM events ORDER BY ts DESC", con)
        con.close()
    except Exception:
        df = pd.DataFrame(columns=COLS)
    df["time"] = pd.to_datetime(df["ts"], unit="s")
    return df

def card(col, title, value, color="#ffffff"):
    col.markdown(f'<div class="card"><h4>{title}</h4>'
                 f'<p style="color:{color}">{value}</p></div>',
                 unsafe_allow_html=True)

# ---------------- Sidebar ----------------
st.sidebar.title("🛡️ Controls")
sev_sel = st.sidebar.multiselect("Severity", list(COLORS), default=list(COLORS))
proto_sel = st.sidebar.multiselect("Protocol", list(ADVICE), default=list(ADVICE))
st.sidebar.caption("Auto-refreshes every 5 seconds.")
st.sidebar.divider()
st.sidebar.subheader("Demo tools")
confirm = st.sidebar.checkbox("I want to clear all events")
if st.sidebar.button("Reset demo data", disabled=not confirm):
    con = sqlite3.connect("events.db")
    con.execute("DELETE FROM events")
    con.commit()
    con.close()
    st.sidebar.success("Events cleared.")

# ---------------- Header ----------------
st.title("🛡️ Sensitive Data Exposure Monitor")
st.caption("Detects sensitive data sent over unencrypted protocols and flags "
           "server misconfigurations. Only masked values are stored.")

@st.fragment(run_every=5)
def live():
    df = load()
    df = df[df.severity.isin(sev_sel) & df.protocol.isin(proto_sel)]
    net = df[df.src_ip != "scanner"]
    scan = df[df.src_ip == "scanner"]
    score = min(100, int(sum(WEIGHT.get(s, 0) for s in df.severity)))
    crit = int((df.severity == "Critical").sum())
    high = int((df.severity == "High").sum())

    if df.empty:
        bg, msg = "#1f2937", "⏳ Waiting for traffic... send some test requests."
    elif crit:
        bg, msg = "#7f1d1d", f"🚨 ACTION REQUIRED: {crit} critical exposure(s) detected"
    elif high:
        bg, msg = "#7c2d12", f"⚠️ {high} high-severity finding(s) need attention"
    else:
        bg, msg = "#14532d", "✅ No critical or high findings"
    st.markdown(f'<div class="banner" style="background:{bg}">{msg}</div>',
                unsafe_allow_html=True)

    c = st.columns(5)
    card(c[0], "Total findings", len(df))
    card(c[1], "Critical", crit, COLORS["Critical"])
    card(c[2], "High", high, COLORS["High"])
    card(c[3], "Hosts involved", net.src_ip.nunique())
    rc = "#ef4444" if score >= 50 else "#eab308" if score >= 20 else "#22c55e"
    card(c[4], "Risk score (0-100)", score, rc)
    st.write("")

    t1, t2, t3 = st.tabs(["📡 Live traffic findings", "🔎 Server scan", "ℹ️ How it works"])

    with t1:
        left, right = st.columns([3, 2])
        with left:
            st.subheader("Findings over time")
            if len(net):
                tl = net.set_index("time").resample("1min").size()
                st.area_chart(tl)
            else:
                st.info("No traffic findings yet.")
            st.subheader("Findings by data type")
            if len(net):
                st.bar_chart(net.data_type.value_counts())
        with right:
            st.subheader("By severity")
            total = max(len(df), 1)
            html = ""
            for s in COLORS:
                n = int((df.severity == s).sum())
                pct = 100 * n / total
                html += (f'<div class="barrow"><div class="barlabel">{ICON[s]} {s}</div>'
                         f'<div class="bartrack"><div class="barfill" '
                         f'style="width:{pct}%;background:{COLORS[s]}"></div></div>'
                         f'<div>{n}</div></div>')
            st.markdown(html, unsafe_allow_html=True)
            st.subheader("Remediation")
            for p in sorted(net.protocol.unique()):
                st.write(f"**{p}**: {ADVICE.get(p, 'Use an encrypted alternative.')}")
            if net.empty:
                st.caption("Advice appears when traffic findings exist.")

        st.subheader("Event log")
        view = net.copy()
        view["level"] = view.severity.map(lambda s: f"{ICON.get(s, '')} {s}")
        st.dataframe(view[["time", "src_ip", "dst_ip", "protocol",
                           "data_type", "masked_sample", "level"]],
                     width="stretch", hide_index=True)
        st.download_button("⬇️ Export CSV", df.to_csv(index=False),
                           "exposure_report.csv", "text/csv")

    with t2:
        st.subheader("Server configuration findings")
        if scan.empty:
            st.info("No scan results. Run: python scanner.py http://192.168.56.102")
        else:
            sv = scan.copy()
            sv["level"] = sv.severity.map(lambda s: f"{ICON.get(s, '')} {s}")
            sv = sv.rename(columns={"data_type": "finding", "dst_ip": "target"})
            st.dataframe(sv[["time", "target", "finding", "level"]],
                         width="stretch", hide_index=True)
            st.markdown("**Fix guide**")
            st.write("- No HTTPS redirect / login over HTTP: deploy TLS and redirect port 80 to 443.")
            st.write("- Missing HSTS: add `Strict-Transport-Security: max-age=31536000`.")
            st.write("- Cookie flags: set `Secure` and `HttpOnly` on session cookies.")

    with t3:
        st.subheader("Pipeline")
        st.markdown(
            "1. **Capture** packets on the lab network (Scapy + Npcap)\n"
            "2. **Filter** plaintext protocols (HTTP, FTP, SMTP, POP3, IMAP)\n"
            "3. **Detect** secrets with regex rules and validators (Luhn for cards)\n"
            "4. **Mask** every value so raw secrets are never stored\n"
            "5. **Deduplicate** repeated findings (10 second window)\n"
            "6. **Store** in SQLite, **score** by severity, **display** here\n"
            "7. **Scan** the server for HTTPS redirect, HSTS and cookie issues")
        st.subheader("Severity levels")
        st.write("🔴 Critical: password, card, Basic auth, FTP login  |  "
                 "🟠 High: PAN, API key, JWT, login form over HTTP  |  "
                 "🟡 Medium: e-mail, missing redirect/cookie flags  |  "
                 "🔵 Low: missing HSTS")
        st.caption("Limitation: encrypted (TLS) traffic is not inspected. "
                   "The tool reports the absence of encryption.")

live()
