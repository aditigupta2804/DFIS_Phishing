# 🛡️ Phishing URL Detection System (PUDS)

A web application that analyses any URL and tells you how likely it is to be a **phishing link**, with a risk score from 0 to 100 and a clear explanation of every red flag found.

Built as the capstone project for the **Infosys Springboard Student Enhancement Program (SEP) – Cyber Security** track.

> The link is **never opened**. Only the structure of the URL is analysed, so scanning is completely safe.

---

## ✨ Features

- **Instant risk score** with a gauge meter and a colour-coded verdict (`SAFE`, `SUSPICIOUS`, `PHISHING`)
- **13 security checks**, each shown as a card with the points it added and the reason
- **URL breakdown**: protocol, domain, path, query and length
- **One-click examples** in the sidebar to try safe and phishing links
- **Bulk scan**: upload a `.txt` / `.csv` file or paste many URLs and scan them all at once
- **Dashboard** with total scans, verdict distribution chart, recent risk scores and scan history
- **Export** scan history and bulk results as CSV
- **Scan history** stored in a local SQLite database, each scan with a unique **SHA-256** based ID

---

## 🧠 How It Works

The URL is split into protocol, hostname and path. Each of the 13 rules below adds risk points if it is triggered. The total (maximum 100) decides the verdict.

| Check | Points | What it looks for |
|---|---|---|
| No HTTPS | 15 | Connection is not encrypted |
| IP address as domain | 25 | `http://192.168.1.5/...` instead of a real domain |
| `@` symbol | 15 | Text before `@` is ignored by browsers and used to hide the real site |
| Long URL | 10 | More than 75 characters |
| Too many subdomains | 10 | More than 4 parts in the hostname |
| Many hyphens | 10 | Two or more hyphens in the domain |
| URL shortener | 15 | `bit.ly`, `tinyurl.com`, etc. hide the destination |
| Risky TLD | 10 | `.xyz`, `.top`, `.tk`, `.click`, etc. |
| Look-alike characters | 10 | Punycode (`xn--`) used for homograph attacks |
| Digits in domain | 5 | Four or more digits in the hostname |
| Suspicious keywords | up to 20 | `login`, `verify`, `secure`, `bank`, `password`, etc. |
| Brand impersonation | 20 | A brand name (PayPal, Amazon...) in the hostname but not as the real domain |
| Path redirect | 5 | Double slash `//` inside the path |

### Verdict

| Score | Verdict |
|---|---|
| 0 – 29 | ✅ SAFE |
| 30 – 59 | ⚠️ SUSPICIOUS |
| 60 – 100 | 🚨 PHISHING |

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Language | Python |
| Web interface | Streamlit |
| Database | SQLite |
| Data handling | Pandas |
| Charts | Altair |
| Security | SHA-256 (hashlib) for scan IDs |

---

## 🚀 Getting Started

### 1. Clone the repository
```bash
git clone https://github.com/aditigupta2804/DFIS_Phishing.git
cd DFIS_Phishing
```

### 2. Install the requirements
```bash
python -m pip install -r requirements.txt
```

### 3. Run the app
```bash
python -m streamlit run app.py
```

Open **http://localhost:8501** in your browser.

The database file (`puds.db`) is created automatically on the first scan.

---

## 🧪 Try These URLs

| URL | Expected result |
|---|---|
| `https://www.google.com` | ✅ SAFE |
| `http://bit.ly/3abc` | ⚠️ SUSPICIOUS |
| `http://192.168.1.5/bank/login` | ⚠️ SUSPICIOUS |
| `http://paypal-secure-login.xyz/verify?account=1` | 🚨 PHISHING |
| `https://secure-update.amazon.com.account-verify.top/login` | 🚨 PHISHING |

---

## 📁 Project Structure

```
DFIS_Phishing/
├── app.py             # Application: detection engine, database and UI
├── requirements.txt   # Python dependencies
├── .gitignore
└── README.md
```

---

## 🔐 Security Concepts Used

- Phishing and social engineering detection
- Input validation and safe URL parsing
- Brand impersonation and homograph (look-alike) attack detection
- SHA-256 hashing for unique scan IDs
- Secure logging of scan history in SQLite

---

## ⚠️ Limitations

This is a **rule-based** detector. It checks the structure of a URL and does not use a live blacklist or machine learning, so it can miss some phishing links or flag a few safe ones. It is meant for learning and awareness, not as a replacement for a professional security product.

### Future Improvements
- Machine learning model trained on a phishing dataset
- Integration with live threat-intelligence feeds
- Domain age and WHOIS checks
- Browser extension

---

## 👩‍💻 Author

**Aditi Kumari**
USN: 1DS24CS007
Department of Computer Science & Engineering
Dayananda Sagar College of Engineering, Bengaluru

Infosys Springboard Student Enhancement Program (SEP) – Cyber Security
