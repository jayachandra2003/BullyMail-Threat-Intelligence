# BullyMail V2 — Intelligent Email Bullying, Phishing & Security Threat Detection System

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Framework: Flask](https://img.shields.io/badge/Framework-Flask_2.x-green.svg)](https://flask.palletsprojects.com/)
[![WSGI: Waitress](https://img.shields.io/badge/WSGI-Waitress_Production-purple.svg)]()
[![Architecture: Modular V2](https://img.shields.io/badge/Architecture-Modular_V2-purple.svg)]()

BullyMail V2 is a multi-vector email threat intelligence and forensics platform designed to protect academic and enterprise communication ecosystems from **cyberbullying, phishing, malicious URLs, look-alike domain spoofing, social engineering manipulation, dangerous attachments, and image tampering**.

---

## 🌟 Key Features in BullyMail V2

1. **Cyberbullying & Harassment Detection:**
   - TF-IDF feature extraction (`ngram_range=(1,2)`, `max_features=4000`) paired with Logistic Regression and Linear Support Vector Machines (SVM).
   - Calibrated exponential rule matching with multi-tier severity differentiation (`MEDIUM`, `HIGH`, `CRITICAL`).
   - Adversarial token de-obfuscation normalizer defeating character-spaced, dotted, and leetspeak evasions.

2. **Dedicated Phishing & Credential Theft Detection:**
   - Scans for credential reset lures, account suspension threats, financial extortion, and display-name vs. public webmail mismatches.
   - Mitigates informational security notices to prevent false positives on legitimate automated alerts.

3. **URL & Link Security Analyzer:**
   - Safe static inspection without dangerous network navigation.
   - Detects raw IP addresses, URL shorteners, punycode homoglyphs, excessive subdomain nesting, and sensitive credential target paths.

4. **Fake / Look-Alike Domain Detector:**
   - Typosquatting and brand spoofing detection using Levenshtein distance and homoglyph substitution mapping against trusted baselines.

5. **Social Engineering Detector:**
   - Identifies psychological coercion: authority impersonation (Deans, IT Administrators), urgency/time pressure, fear/intimidation, financial extortion, and reward traps.

6. **Safe Static Attachment & Malware Analysis:**
   - Never executes uploaded files.
   - Scans for double extensions (`invoice.pdf.exe`), PE headers (`MZ`), macro APIs (`Shell`, `AutoExec`), and calculates MD5/SHA-256 hashes.

7. **Passive Image Forensics:**
   - EXIF metadata extraction, editing software signatures (Photoshop, GIMP), and compression variance analysis.

8. **Unified Risk Engine & Explainable AI (XAI):**
   - Transparent scoring strategy aggregating all 6 specialized detectors.
   - Generates granular, plain-English evidence summaries with printable PDF and CSV export capabilities.

9. **Robust Security & Dual Database Support:**
   - Werkzeug PBKDF2/SHA256 password hashing, brute-force rate limiting with IP/User lockout, `.env` secret management, and dual database support (MySQL `utf8mb4` with automatic SQLite local fallback).

---

## 🚀 Quick Start Guide

### Prerequisites
- Python 3.8+ installed on Windows / Linux / macOS.
- (Optional) MySQL 5.7+ / 8.0+ server (SQLite fallback works automatically without setup).

### 1. Installation
Run the automated batch file or follow manual steps:
```bash
# Windows (Automated Virtual Environment & Dependency Setup)
Install_Dependencies.bat

# Or Manual Setup:
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python -c "import nltk; nltk.download('punkt'); nltk.download('stopwords')"
```

### 2. Configuration (`.env`)
Copy `.env.example` to `.env` and adjust configuration values:
```env
FLASK_ENV=development
SECRET_KEY=bullymail_v2_secure_secret_key_2026

# Administrator Credentials
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your_secure_password_here

# Database Configuration (MySQL or local SQLite fallback)
DB_TYPE=mysql
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=root
DB_NAME=bullymail_db
```
*(If MySQL is not running or credentials differ, BullyMail automatically transitions to local SQLite without crashing).*

### 3. Database Initialization (MySQL)
If using MySQL, run:
```bash
mysql -u root -p < database_setup.sql
```

### 4. Running the Application

#### Option A: Production WSGI Server (Waitress)
```bash
# Windows Production Launcher:
Run_BullyMail_Production.bat

# Or Manual WSGI Startup:
python wsgi.py
```

#### Option B: Development / Local Demo Server
```bash
# Windows Development Launcher:
Run_BullyMail.bat

# Or Manual Python:
python run.py
```
Access the application at **`http://localhost:5000`**.

Administrator Authentication:
* Initial administrator credentials are set via `ADMIN_USERNAME` and `ADMIN_PASSWORD` in `.env`.
* If `ADMIN_PASSWORD` is omitted during local development startup, a secure temporary password is automatically generated and displayed in the startup console banner.

---

## 🧪 Automated Testing
BullyMail V2 includes automated test coverage with Pytest:
```bash
pytest tests/ -v
```
Tests cover:
- Authentication, password hashing, and brute-force rate limiting.
- Atomic model and vectorizer loading integrity.
- All 6 threat detectors individually.
- Unified Risk Engine and API endpoints.
- 64-case adversarial stress matrix and realistic scenario test cases.

---

## 📁 Project Architecture

```
bullymail/
├── config.py             # Centralized environment configuration
├── database/             # Dual DB connection pool (MySQL + SQLite)
├── models/               # Data access objects (User, Analysis)
├── routes/               # Modular Flask Blueprints (auth, analysis, models, datasets, reports, email)
├── services/             # 6 Threat detection engines + Unified Risk Engine + XAI
├── static/               # Modern CSS & modular JS
└── templates/            # Jinja2 templates (index, login, dashboard, printable reports)
archive/
└── v1/                   # Archived legacy V1 monolithic reference files
```

---

## 📄 Documentation Reference
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — Architectural design and threat pipeline data flow.
- **[SECURITY.md](SECURITY.md)** — Threat model, security controls, and safe file handling.
- **[ML_METHODOLOGY.md](ML_METHODOLOGY.md)** — NLP methodology, metric calculation, and XAI.
- **[API_DOCUMENTATION.md](API_DOCUMENTATION.md)** — REST API endpoint reference.
