"""
PUDS - Phishing URL Detection System
Infosys Springboard SEP - Cyber Security Capstone Project
Tech: Python, Streamlit, SQLite, SHA-256, Pandas, Altair
"""
import re
import html
import sqlite3
import hashlib
from datetime import datetime
from urllib.parse import urlparse

import altair as alt
import pandas as pd
import streamlit as st

DB_FILE = "puds.db"

SUSPICIOUS_WORDS = ["login", "signin", "verify", "update", "secure", "account", "bank",
                    "free", "bonus", "password", "confirm", "wallet", "suspend", "prize"]
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rebrand.ly"]
RISKY_TLDS = [".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".click", ".work", ".zip", ".buzz"]
BRANDS = ["paypal", "google", "amazon", "facebook", "microsoft", "apple", "netflix",
          "instagram", "paytm", "hdfc", "icici", "sbi", "flipkart"]
EXAMPLES = [
    ("✅ Google", "https://www.google.com"),
    ("⚠️ Short link", "http://bit.ly/3abc"),
    ("🚨 Fake PayPal", "http://paypal-secure-login.xyz/verify?account=1"),
    ("🚨 Fake Amazon", "https://secure-update.amazon.com.account-verify.top/login"),
    ("🚨 IP address", "http://192.168.1.5/bank/login"),
]
COLORS = {"SAFE": "#22c55e", "SUSPICIOUS": "#f59e0b", "PHISHING": "#ef4444"}


# ============================================================ DATABASE
def init_db():
    con = sqlite3.connect(DB_FILE)
    con.execute("""CREATE TABLE IF NOT EXISTS scans (
        scan_id TEXT, url TEXT, score INTEGER, verdict TEXT, scanned_at TEXT)""")
    con.commit()
    con.close()


def save_scan(url, score, verdict):
    now = datetime.now()
    scan_id = hashlib.sha256((url + str(now)).encode()).hexdigest()[:16]
    con = sqlite3.connect(DB_FILE)
    con.execute("INSERT INTO scans VALUES (?,?,?,?,?)",
                (scan_id, url, score, verdict, now.strftime("%Y-%m-%d %H:%M:%S")))
    con.commit()
    con.close()
    return scan_id


def load_scans():
    con = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT * FROM scans ORDER BY scanned_at DESC", con)
    con.close()
    return df


def clear_scans():
    con = sqlite3.connect(DB_FILE)
    con.execute("DELETE FROM scans")
    con.commit()
    con.close()


# ============================================================ DETECTION ENGINE
def analyze(url):
    """Returns (score 0-100, verdict, checks, parts)."""
    url = url.strip()
    full = url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url) else "http://" + url
    parsed = urlparse(full)
    host = (parsed.hostname or "").lower()
    labels = [x for x in host.split(".") if x]
    reg_label = labels[-2] if len(labels) >= 2 else host
    low = url.lower()
    checks = []

    def add(name, icon, hit, pts, detail_hit, detail_ok):
        checks.append({"name": name, "icon": icon, "hit": bool(hit),
                       "pts": pts if hit else 0, "detail": detail_hit if hit else detail_ok})

    add("HTTPS encryption", "🔒", not full.startswith("https://"), 15,
        "Connection is not encrypted (no HTTPS)", "Uses a secure HTTPS connection")
    add("IP address as domain", "🌐", re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host), 25,
        "Real sites use domain names, not raw IP addresses", "Uses a proper domain name")
    add("'@' symbol", "📧", "@" in url, 15,
        "Text before '@' is ignored by browsers - used to hide the real site", "No '@' symbol found")
    add("URL length", "📏", len(url) > 75, 10,
        f"URL is {len(url)} characters long (over 75)", f"URL length is normal ({len(url)} chars)")
    add("Subdomains", "🧩", len(labels) > 4, 10,
        f"{len(labels)} parts in hostname - too many subdomains", "Normal number of subdomains")
    add("Hyphens in domain", "➖", host.count("-") >= 2, 10,
        f"{host.count('-')} hyphens in the hostname", "Few or no hyphens in the domain")
    add("URL shortener", "🔗", host in SHORTENERS, 15,
        "Shortened links hide the real destination", "Not a shortened link")
    add("Risky TLD", "🏷️", any(host.endswith(t) for t in RISKY_TLDS), 10,
        "Domain ends with a TLD often abused by attackers", "Domain extension looks normal")
    add("Look-alike characters", "🔤", "xn--" in host, 10,
        "Punycode found - possible homograph attack", "No look-alike (punycode) characters")
    add("Digits in domain", "🔢",
        sum(c.isdigit() for c in host) >= 4 and not re.fullmatch(r"[\d.]+", host), 5,
        "Many digits in the hostname", "Normal use of digits")
    found = [w for w in SUSPICIOUS_WORDS if w in low]
    add("Suspicious keywords", "🔑", found, min(5 * len(found), 20),
        "Found: " + ", ".join(found), "No phishing-style keywords found")
    brand = [b for b in BRANDS if b in host and reg_label != b]
    add("Brand impersonation", "🎭", brand, 20,
        f"'{brand[0] if brand else ''}' is in the hostname but the real domain is '{reg_label}'",
        "No brand impersonation detected")
    add("Path redirect", "↪️", "//" in parsed.path, 5,
        "Double slash in path may indicate a redirect", "No suspicious redirect pattern")

    score = min(sum(c["pts"] for c in checks), 100)
    verdict = "SAFE" if score < 30 else "SUSPICIOUS" if score < 60 else "PHISHING"
    parts = {"Protocol": parsed.scheme.upper(), "Domain": host or "-",
             "Path": parsed.path or "/", "Query": parsed.query or "-", "Length": f"{len(url)} chars"}
    return score, verdict, checks, parts


ADVICE = {
    "SAFE": "No major red flags found. Still, always check the address bar and avoid sharing passwords through links you did not expect.",
    "SUSPICIOUS": "Several warning signs found. Do not enter personal details. Open the official website by typing its address yourself.",
    "PHISHING": "Very likely a phishing link. Do NOT open it or enter any information. Report it and delete the message.",
}


# ============================================================ UI HELPERS
def gauge(score, verdict):
    c = COLORS[verdict]
    arc = 282.7
    return (f'<div class="card gauge"><svg viewBox="0 0 220 135" width="100%">'
            f'<path d="M20 115 A90 90 0 0 1 200 115" fill="none" stroke="#1e293b" stroke-width="16" stroke-linecap="round"/>'
            f'<path d="M20 115 A90 90 0 0 1 200 115" fill="none" stroke="{c}" stroke-width="16" stroke-linecap="round" '
            f'stroke-dasharray="{score / 100 * arc:.1f} {arc}"/>'
            f'<text x="110" y="95" text-anchor="middle" font-size="40" font-weight="700" fill="#f1f5f9">{score}</text>'
            f'<text x="110" y="115" text-anchor="middle" font-size="11" fill="#94a3b8">RISK SCORE / 100</text></svg>'
            f'<div class="badge" style="background:{c}22;color:{c};border:1px solid {c}">{verdict}</div></div>')


def kpi(label, value, color="#38bdf8"):
    return (f'<div class="card kpi"><div class="kpi-v" style="color:{color}">{value}</div>'
            f'<div class="kpi-l">{label}</div></div>')


def check_card(c):
    col = "#ef4444" if c["hit"] else "#22c55e"
    tag = f"+{c['pts']} pts" if c["hit"] else "Passed"
    return (f'<div class="chk" style="border-left:4px solid {col}">'
            f'<div class="chk-h"><span>{c["icon"]} {c["name"]}</span>'
            f'<span class="tag" style="color:{col}">{tag}</span></div>'
            f'<div class="chk-d">{html.escape(c["detail"])}</div></div>')


def html_table(df, cols):
    head = "".join(f"<th>{c}</th>" for c in cols)
    rows = ""
    for _, r in df.iterrows():
        tds = ""
        for c in cols:
            v = html.escape(str(r[c]))
            if c.lower() == "verdict":
                col = COLORS.get(str(r[c]), "#94a3b8")
                v = f'<span class="pill" style="background:{col}22;color:{col}">{v}</span>'
            tds += f"<td>{v}</td>"
        rows += f"<tr>{tds}</tr>"
    return f'<div class="tbl-wrap"><table class="tbl"><tr>{head}</tr>{rows}</table></div>'


CSS = """
<style>
#MainMenu, footer {visibility:hidden;}
header[data-testid="stHeader"] {background:transparent;}
.stApp {background:radial-gradient(1200px 600px at 10% -10%, #12315a 0%, transparent 60%),
        radial-gradient(900px 500px at 100% 0%, #3b1d5e 0%, transparent 55%), #070d1a;}
.stApp, .stApp p, .stApp label, .stApp li, .stApp h1, .stApp h2, .stApp h3, .stApp h4,
[data-testid="stMarkdownContainer"], [data-testid="stWidgetLabel"] p {color:#e2e8f0;}
.block-container {padding-top:1.5rem; max-width:1150px;}
[data-testid="stSidebar"] {background:#0a1226; border-right:1px solid #1e293b;}
.hero {background:linear-gradient(120deg,#0ea5e9 0%,#6366f1 55%,#a855f7 100%); border-radius:18px;
       padding:26px 30px; margin-bottom:18px; box-shadow:0 10px 40px #0ea5e944;}
.hero h1 {margin:0; font-size:2rem; color:#fff !important;}
.hero p {margin:6px 0 0 0; color:#e0f2fe !important; font-size:1rem;}
.card {background:#0f1a2e; border:1px solid #1e3050; border-radius:14px; padding:16px;}
.gauge {text-align:center;}
.badge {display:inline-block; padding:5px 18px; border-radius:999px; font-weight:700; letter-spacing:1px; margin-top:2px;}
.kpi {text-align:center;} .kpi-v {font-size:2rem; font-weight:700;} .kpi-l {color:#94a3b8; font-size:.85rem;}
.info-row {display:flex; justify-content:space-between; gap:12px; padding:7px 0; border-bottom:1px solid #1e293b; font-size:.9rem;}
.info-row:last-child {border-bottom:none;} .info-k {color:#94a3b8;} .info-v {color:#e2e8f0; word-break:break-all; text-align:right;}
.advice {border-radius:12px; padding:14px 16px; margin:14px 0; font-size:.95rem;}
.chk {background:#0f1a2e; border:1px solid #1e3050; border-radius:10px; padding:10px 14px; margin-bottom:10px;}
.chk-h {display:flex; justify-content:space-between; font-weight:600;} .tag {font-size:.8rem; font-weight:700;}
.chk-d {color:#94a3b8; font-size:.85rem; margin-top:3px;}
.sec {font-size:1.15rem; font-weight:700; margin:18px 0 10px 0;}
.tbl-wrap {overflow-x:auto; border:1px solid #1e3050; border-radius:12px;}
.tbl {width:100%; border-collapse:collapse; font-size:.85rem; background:#0f1a2e;}
.tbl, .tbl tr, .tbl th, .tbl td {border-left:none !important; border-right:none !important;}
.tbl {border:none !important;}
.tbl th {text-align:left; padding:10px 12px; background:#13233f; color:#93c5fd; border-top:none !important; border-bottom:none !important;}
.tbl td {padding:9px 12px; border-top:1px solid #1e293b !important; border-bottom:none !important; color:#e2e8f0; word-break:break-all;}
.pill {padding:2px 10px; border-radius:999px; font-weight:700; font-size:.75rem;}
.stTextInput input {background:#0f1a2e !important; color:#f1f5f9 !important; border:1px solid #2b4a7a !important;
                    border-radius:12px !important; padding:14px !important; font-size:1rem !important;}
.stTextInput input:focus {border-color:#38bdf8 !important; box-shadow:0 0 0 2px #38bdf855 !important;}
.stButton > button, .stDownloadButton > button {border-radius:12px; font-weight:600; border:1px solid #2b4a7a;
                    background:#13233f; color:#e2e8f0;}
.stButton > button:hover, .stDownloadButton > button:hover {border-color:#38bdf8; color:#fff;}
.stButton > button[kind="primary"] {background:linear-gradient(90deg,#0ea5e9,#6366f1); border:none; color:#fff; padding:.55rem 1.4rem;}
.stTabs [data-baseweb="tab-list"] {gap:6px;}
.stTabs [data-baseweb="tab"] {background:#0f1a2e; border-radius:10px 10px 0 0; padding:10px 18px; color:#94a3b8;}
.stTabs [aria-selected="true"] {background:#13233f; color:#38bdf8 !important;}
[data-testid="stFileUploaderDropzone"] {background:#0f1a2e; border:1px dashed #2b4a7a;}
[data-testid="stFileUploaderDropzone"] * {color:#cbd5e1 !important;}
[data-testid="stFileUploaderDropzone"] button {background:#1d4ed8; color:#fff !important; border:none;}
.small {color:#64748b; font-size:.8rem;}
</style>
"""


def set_example(u):
    st.session_state["url_input"] = u
    st.session_state["auto"] = True


# ============================================================ APP
st.set_page_config(page_title="PUDS - Phishing URL Detector", page_icon="🛡️", layout="wide")
st.markdown(CSS, unsafe_allow_html=True)
init_db()

with st.sidebar:
    st.markdown("### 🛡️ PUDS")
    st.caption("Phishing URL Detection System")
    st.markdown('<div class="sec">Try an example</div>', unsafe_allow_html=True)
    for label, u in EXAMPLES:
        st.button(label, key="ex_" + u, on_click=set_example, args=(u,), width="stretch")
    st.markdown('<div class="sec">Risk levels</div>', unsafe_allow_html=True)
    st.markdown('<span class="pill" style="background:#22c55e22;color:#22c55e">0-29 SAFE</span><br><br>'
                '<span class="pill" style="background:#f59e0b22;color:#f59e0b">30-59 SUSPICIOUS</span><br><br>'
                '<span class="pill" style="background:#ef444422;color:#ef4444">60-100 PHISHING</span>',
                unsafe_allow_html=True)
    st.markdown('<p class="small" style="margin-top:18px">Infosys Springboard SEP<br>Cyber Security Capstone</p>',
                unsafe_allow_html=True)

st.markdown('<div class="hero"><h1>🛡️ Phishing URL Detection System</h1>'
            '<p>Paste any link and get an instant risk score, with a clear explanation of every red flag.</p></div>',
            unsafe_allow_html=True)

tab1, tab2, tab3, tab4 = st.tabs(["🔍 Scan URL", "📦 Bulk Scan", "📊 Dashboard", "ℹ️ About"])

# ---------------------------------------------------------------- Scan
with tab1:
    url = st.text_input("Enter a URL to scan", key="url_input",
                        placeholder="e.g. http://paypal-secure-login.xyz/verify?account=1")
    go = st.button("🔍 Scan URL", type="primary")
    auto = st.session_state.pop("auto", False)
    if (go or auto) and url.strip():
        score, verdict, checks, parts = analyze(url)
        scan_id = save_scan(url.strip(), score, verdict)
        col = COLORS[verdict]
        left, right = st.columns([1, 1.4])
        with left:
            st.markdown(gauge(score, verdict), unsafe_allow_html=True)
            st.markdown(f'<p class="small" style="text-align:center;margin-top:8px">Scan ID (SHA-256): {scan_id}</p>',
                        unsafe_allow_html=True)
        with right:
            rows = "".join(f'<div class="info-row"><span class="info-k">{k}</span>'
                           f'<span class="info-v">{html.escape(v)}</span></div>' for k, v in parts.items())
            st.markdown(f'<div class="card"><b>🔎 URL breakdown</b><div style="margin-top:8px">{rows}</div></div>',
                        unsafe_allow_html=True)
        st.markdown(f'<div class="advice" style="background:{col}18;border:1px solid {col};">'
                    f'<b style="color:{col}">{verdict}</b> &nbsp; {ADVICE[verdict]}</div>', unsafe_allow_html=True)
        triggered = sum(c["hit"] for c in checks)
        st.markdown(f'<div class="sec">Security checks &nbsp;<span class="small">{triggered} of {len(checks)} triggered</span></div>',
                    unsafe_allow_html=True)
        c1, c2 = st.columns(2)
        for i, c in enumerate(checks):
            (c1 if i % 2 == 0 else c2).markdown(check_card(c), unsafe_allow_html=True)
    elif go:
        st.warning("Please enter a URL first.")
    else:
        st.markdown('<div class="card" style="text-align:center;padding:30px;color:#94a3b8">'
                    '👆 Enter a URL above, or pick an example from the sidebar.</div>', unsafe_allow_html=True)

# ---------------------------------------------------------------- Bulk
with tab2:
    st.markdown('<div class="sec">Scan many URLs at once</div>', unsafe_allow_html=True)
    st.caption("Upload a .txt or .csv file with one URL per line, or paste URLs below.")
    f = st.file_uploader("Upload file", type=["txt", "csv"])
    pasted = st.text_area("...or paste URLs (one per line)", height=120)
    urls = []
    if f is not None:
        urls += [l.strip() for l in f.getvalue().decode("utf-8", errors="ignore").splitlines() if l.strip()]
    urls += [l.strip() for l in pasted.splitlines() if l.strip()]
    if st.button("Scan all", type="primary") and urls:
        out = []
        for u in urls[:200]:
            s, v, _, _ = analyze(u)
            save_scan(u, s, v)
            out.append({"URL": u, "Score": s, "Verdict": v})
        res = pd.DataFrame(out)
        k1, k2, k3 = st.columns(3)
        k1.markdown(kpi("URLs scanned", len(res)), unsafe_allow_html=True)
        k2.markdown(kpi("Phishing", int((res.Verdict == "PHISHING").sum()), "#ef4444"), unsafe_allow_html=True)
        k3.markdown(kpi("Safe", int((res.Verdict == "SAFE").sum()), "#22c55e"), unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown(html_table(res, ["URL", "Score", "Verdict"]), unsafe_allow_html=True)
        st.download_button("⬇️ Download results (CSV)", res.to_csv(index=False), "puds_bulk_results.csv", "text/csv")

# ---------------------------------------------------------------- Dashboard
with tab3:
    df = load_scans()
    if df.empty:
        st.markdown('<div class="card" style="text-align:center;padding:30px;color:#94a3b8">'
                    'No scans yet. Scan a URL to see statistics here.</div>', unsafe_allow_html=True)
    else:
        k = st.columns(4)
        k[0].markdown(kpi("Total scans", len(df)), unsafe_allow_html=True)
        k[1].markdown(kpi("Phishing", int((df.verdict == "PHISHING").sum()), "#ef4444"), unsafe_allow_html=True)
        k[2].markdown(kpi("Suspicious", int((df.verdict == "SUSPICIOUS").sum()), "#f59e0b"), unsafe_allow_html=True)
        k[3].markdown(kpi("Safe", int((df.verdict == "SAFE").sum()), "#22c55e"), unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)
        a, b = st.columns(2)
        counts = df.verdict.value_counts().rename_axis("verdict").reset_index(name="count")
        dom, rng = list(COLORS.keys()), list(COLORS.values())
        with a:
            st.markdown('<div class="sec">Verdict distribution</div>', unsafe_allow_html=True)
            donut = alt.Chart(counts).mark_arc(innerRadius=60).encode(
                theta="count:Q", color=alt.Color("verdict:N", scale=alt.Scale(domain=dom, range=rng),
                                                 legend=alt.Legend(labelColor="#e2e8f0", title=None)),
                tooltip=["verdict", "count"]).properties(height=260, background="transparent")
            st.altair_chart(donut, width="stretch")
        with b:
            st.markdown('<div class="sec">Risk score of recent scans</div>', unsafe_allow_html=True)
            recent = df.head(15).iloc[::-1].reset_index(drop=True)
            recent["n"] = recent.index + 1
            bars = alt.Chart(recent).mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4).encode(
                x=alt.X("n:O", title="Scan", axis=alt.Axis(labelColor="#94a3b8", titleColor="#94a3b8", labelAngle=0)),
                y=alt.Y("score:Q", title="Score", scale=alt.Scale(domain=[0, 100]),
                        axis=alt.Axis(labelColor="#94a3b8", titleColor="#94a3b8", gridColor="#1e293b")),
                color=alt.Color("verdict:N", scale=alt.Scale(domain=dom, range=rng), legend=None),
                tooltip=["url", "score", "verdict"]).properties(height=260, background="transparent")
            st.altair_chart(bars, width="stretch")
        st.markdown('<div class="sec">Recent scans</div>', unsafe_allow_html=True)
        show = df.head(10).rename(columns={"scan_id": "Scan ID", "url": "URL", "score": "Score",
                                           "verdict": "Verdict", "scanned_at": "Time"})
        st.markdown(html_table(show, ["Time", "URL", "Score", "Verdict", "Scan ID"]), unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)
        d1, d2, _ = st.columns([1, 1, 3])
        d1.download_button("⬇️ Export history (CSV)", df.to_csv(index=False), "puds_history.csv", "text/csv")
        if d2.button("🗑️ Clear history"):
            clear_scans()
            st.rerun()

# ---------------------------------------------------------------- About
with tab4:
    st.markdown("""
<div class="card">
<b>How it works</b><br><br>
The URL is split into protocol, hostname and path, then tested with <b>13 security rules</b>.
Every rule that triggers adds risk points; the total (max 100) decides the verdict.
The link is <b>never opened</b> - only its structure is analysed, so scanning is safe.
</div>
<br>
<div class="card">
<b>Concepts used</b><br><br>
Phishing and social engineering detection &nbsp;•&nbsp; Input validation &nbsp;•&nbsp; Brand impersonation and homograph checks
&nbsp;•&nbsp; SHA-256 hashing for unique scan IDs &nbsp;•&nbsp; Secure logging of scan history in SQLite
</div>
<br>
<div class="card">
<b>Tech stack</b><br><br>
Python &nbsp;•&nbsp; Streamlit &nbsp;•&nbsp; SQLite &nbsp;•&nbsp; Pandas &nbsp;•&nbsp; Altair
</div>
""", unsafe_allow_html=True)
