# BullyMail — Threat Intelligence & Cyberbullying Detection Platform

[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Framework: Flask](https://img.shields.io/badge/Framework-Flask_3.x-green.svg)](https://flask.palletsprojects.com/)
[![Database: MySQL / SQLite](https://img.shields.io/badge/Database-MySQL_%7C_SQLite_Fallback-orange.svg)]()
[![Security: Fernet_AES--128_%26_RBAC](https://img.shields.io/badge/Security-Fernet_AES--128_%26_RBAC-red.svg)]()
[![Automated Tests: Pytest](https://img.shields.io/badge/Tests-256%20Passed-brightgreen.svg)]()

BullyMail is an enterprise digital forensic email threat intelligence and cyberbullying detection platform engineered for multi-tenant educational institutions and collaborative organizations. It continuously ingests communications, decomposes multi-vector attack surfaces, performs hybrid linguistic machine learning and forensic signal analysis, and provides explainable threat assessments through an interactive Security Operations Center (SOC) dashboard.

---

## 1. Project Overview

Academic institutions and corporate enterprises face a compounding convergence of email-borne threats ranging from hostile cyberbullying and targeted harassment to deceptive phishing lures, typosquatted brand domains, psychological social engineering coercion, and malicious file attachments.

BullyMail addresses these challenges through a modular, service-oriented multi-vector architecture:
- **Continuous Ingestion:** Synchronizes institutional mailboxes over IMAP SSL with delta UID tracking and memory-safe streaming MIME parsing.
- **Parallel Forensic Decomposition:** Evaluates incoming communications across specialized threat vectors (NLP Cyberbullying, Phishing, Social Engineering, Static Attachment Forensics, Passive Image Forensics).
- **Explainable Threat Fusion:** Fuses sub-vector signals using a transparent risk aggregation engine, generating calibrated threat scores $[0.0, 1.0]$ and severity ratings (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **Encrypted Multi-Tenancy:** Persists telemetry, message state, and incident records in a relational schema (MySQL with SQLite fallback) with Fernet AES-128 credential encryption.
- **SOC Mission Control:** Delivers real-time posture assessments, segmented severity distributions, ingestion velocity trend charts, and live incident stream ledgers.

---

## 2. Core Features & Threat Vectors

### A. Linguistic Cyberbullying & Harassment NLP Engine
- **Supervised ML Classification:** Combines TF-IDF feature extraction (`ngram_range=(1, 3)`, sublinear term frequency) with calibrated **Logistic Regression** and **Linear Support Vector Classifiers (Linear SVC)** with balanced class weighting.
- **Hierarchical Rule Taxonomy:** Deterministic pattern matching across physical violence, targeted harassment, severe profanity, and hate speech.
- **Morphological Word-Family Matching:** Expands violent root terms (*kill, kills, killed, killing, killer; murder, murdered; stab, stabbed, stabbing*) to enforce high recall on explicit physical threats.
- **Hybrid Confidence Arbitration:** Decision fusion that arbitrates between statistical ML probabilities and deterministic safety overrides.

### B. Phishing & Brand Spoofing Detector
- **Domain Typosquatting Analysis:** Evaluates domain similarity using normalized Levenshtein edit distance against trusted brand baselines without external API lookups.
- **Lexical URL Forensics:** Detects raw IP-in-URL hostnames, deep subdomain nesting, credential-stealing query strings, and suspicious top-level domains (`.xyz`, `.top`, `.tk`).
- **URL Shannon Entropy:** Calculates entropy distributions on hostnames to flag algorithmic domain generation (DGA) and obfuscated redirectors.

### C. Social Engineering & Coercion Detector
- **Artificial Urgency & Time Pressure:** Detects psychological traps (*"within 24 hours"*, *"immediate action required"*).
- **Authority Impersonation:** Flags unauthorized claims of institutional leadership (*Dean, Chancellor, IT Support, Security Desk*).
- **Financial & Credential Baiting:** Identifies wire transfer requests, password verification traps, and extortion language.

### D. Static Attachment Malware Forensics
- **Zero-Execution Guarantee:** Analyzes binaries strictly in memory buffers without executing untrusted files on the host OS.
- **Magic Byte Verification:** Validates file signatures (`MZ` for PE executables, `ELF` headers) against declared MIME types.
- **Double Extension Cloaking:** Detects obfuscated filenames (e.g., `document.pdf.exe`, `invoice.xlsx.vbs`).
- **Binary Entropy & Script Scanning:** Measures file byte entropy and scans for embedded script execution tags (`powershell`, `cmd`, `eval()`).

### E. Passive Image Forensics
- **EXIF Metadata Extraction:** In-memory decoding of EXIF tags (Camera Make, Software, GPS Coordinates, Timestamp).
- **Anomaly Detection:** Flags compression quality variance and embedded script blocks within image binary streams.

---

## 3. System Architecture & Processing Flow

```
[ Email Ingestion: Manual Input / File Intake / Background IMAP SSL ]
                              │
                              ▼
           [ SafeMIMEParser (RFC 822 Decomposition) ]
                              │
                              ▼
           [ IngestedMessage State (CLAIMED -> PROCESSING) ]
                              │
                              ▼
            ┌─────────────────┴─────────────────┐
            │       UnifiedRiskEngine           │
            ├───────────────────────────────────┤
            │ • BullyingDetector (TF-IDF + ML)  │
            │ • PhishingDetector (Typosquatting)│
            │ • SocialEngineeringDetector       │
            │ • AttachmentAnalyzer (Magic Bytes)│
            │ • ImageForensicsAnalyzer (EXIF)   │
            └─────────────────┬─────────────────┘
                              │
                              ▼
        [ Multi-Vector Risk Aggregation & Explainable Scoring ]
                              │
                              ▼
         [ AnalysisModel (Encrypted Relational Persistence) ]
                              │
                              ▼
       [ SOC Dashboard • Incident Workflow • Warning Dispatch ]
```

---

## 4. Threat Analyzer & Investigation Console

The Digital Forensic Investigation Console (`/dashboard#tab-analyze`) provides interactive threat investigation:
- **Intake Form:** Subject, Sender Identity, Target Recipient, and Message Body Payload.
- **Compact Attachment Controls:** Memory-safe file attachments and image uploads for static inspection.
- **Engine Selection:**
  - **`NORMAL` Mode (Default):** Runs the full multi-vector ML classifier and forensic rule engine, persisting results to the database and updating SOC telemetry.
  - **`AI` Mode (Optional / Experimental):** Provides on-demand zero-shot semantic threat classification via OpenRouter, displaying an isolated evaluation card without writing persistent database records.
- **Explainable Result Card:** Displays Threat Detection status, Severity badge, Confidence score, Threat Categories, and human-readable forensic justification indicators.

---

## 5. Autonomous Synchronization & Concurrency Leases

BullyMail implements a robust, distributed background ingestion daemon (`bullymail/worker/daemon.py`):
- **15-Second Polling Cycle:** Regularly checks active institutional mailboxes across registered tenants.
- **IMAP Delta Optimization:** Connects over SSL on port 993, tracks `UIDVALIDITY`, queries `MAX(imap_uid)` from `ingested_messages`, and downloads only `UID > last_known_uid`, achieving sub-3-second sync times per mailbox.
- **Atomic Concurrency Leases:** Uses atomic conditional SQL updates with a 2-minute time-to-live (`sync_lease_expires_at = NOW() + 2 minutes`) to prevent concurrent worker collisions without external distributed lock managers.
- **Telemetry Heartbeat & Auto-Healing:** Active batch processing renews lease timestamps. If an unexpected process crash occurs, expired leases are automatically recovered on the subsequent polling cycle.
- **Strict `try...finally` Guarantees:** Guarantees that `release_sync_lease()` is unconditionally executed upon completion or error, ensuring mailboxes never remain trapped in a `"Syncing..."` state.

---

## 6. Multi-Tenant Database & Security Architecture

### Relational Schema Design
- `institutions`: Multi-tenant organization boundaries and domain configurations.
- `users`: User identities with cryptographic password hashes, verification state, and RBAC tiers (`admin`, `analyst`, `operator`).
- `email_config`: Institutional mailbox settings, encrypted credentials, sync statuses, and lease locks.
- `ingested_messages`: Raw message tracking, IMAP UIDs, folder `UIDVALIDITY`, and processing states.
- `analyzed_emails`: Structured forensic reports, multi-vector scores, severity levels, and incident review statuses.
- `audit_logs`: Immutable audit trails for administrative decisions and security events.

### Cryptographic Security & Credential Protection
- **Fernet Symmetric Encryption:** Mailbox app-passwords stored in `email_config` are encrypted at rest using AES-128-CBC with HMAC-SHA256 authenticated integrity.
- **PBKDF2 Key Derivation:** Cryptographic keys are derived from `BULLYMAIL_MASTER_KEY` using PBKDF2 with SHA-256 and 100,000 salt iterations.
- **Password Hashing:** User passwords are encrypted with salted PBKDF2-HMAC-SHA256 hashes.
- **API Rate Limiting:** Sliding-window rate limiters defend authentication routes against brute-force attacks and credential stuffing.

---

## 7. Installation & Quick Start

### Prerequisites
- Python 3.10 or higher
- Git
- MySQL 8.0+ (Optional: SQLite is used automatically in development mode)

### 1. Clone the Repository
```bash
git clone https://github.com/jayachandra2003/BullyMail-Threat-Intelligence.git
cd BullyMail-Threat-Intelligence
```

### 2. Create and Activate Virtual Environment
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Copy `.env.example` to `.env` and configure your settings:
```bash
cp .env.example .env
```

Generate a secure master encryption key:
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```
Place the output in `.env` under `BULLYMAIL_MASTER_KEY`.

### 5. Start the Application
```bash
# Start Flask Web Application
python app.py
```
Open your browser and navigate to: `http://localhost:5000`

### 6. (Optional) Run the Autonomous Background Worker
In a separate terminal:
```bash
python -m bullymail.worker.daemon
```

---

## 8. Environment Variables Reference

| Variable Name | Description | Default / Example |
|---|---|---|
| `FLASK_ENV` | Application environment (`development` / `production`) | `development` |
| `SECRET_KEY` | Flask session encryption secret | *Random secret string* |
| `BULLYMAIL_MASTER_KEY` | Base64 Fernet key for encrypting mailbox credentials | *Base64 32-byte key* |
| `DB_TYPE` | Relational database engine (`sqlite` or `mysql`) | `sqlite` |
| `SQLITE_DB_PATH` | SQLite database file path | `bullymail.db` |
| `DB_HOST` / `DB_PORT` | MySQL connection host and port | `localhost` / `3306` |
| `DB_USER` / `DB_PASSWORD` | MySQL database user and password | `root` / `password` |
| `DB_NAME` | MySQL database name | `bullymail_db` |
| `WORKER_POLL_INTERVAL` | Autonomous worker polling frequency in seconds | `15` |
| `OPENROUTER_API_KEY` | *(Optional)* API key for experimental AI evaluation mode | `sk-or-v1-...` |

---

## 9. Automated Testing & Verification

BullyMail maintains a rigorous test suite of **256 automated unit and integration tests** verifying all forensic engines, cryptographic services, database migrations, IMAP sync protocols, and concurrency leases.

Run the test suite:
```bash
# Run complete test suite in quiet mode
pytest -q

# Run specific forensic tests
pytest tests/test_risk_engine.py tests/test_ml_models.py -v

# Run concurrency and worker daemon tests
pytest tests/test_worker_daemon.py tests/test_phase1d_mailbox_management.py -v
```

---

## 10. Repository Directory Layout

```
bullymail/
├── config.py                 # Configuration loader & environment bindings
├── database/
│   ├── connection.py         # Dynamic SQLite/MySQL connection pool & dialect abstraction
│   ├── schema.py             # DDL table definitions & foreign key constraints
│   └── migrations.py         # Schema migration & upgrade routines
├── models/
│   ├── analysis.py           # Analyzed email persistence & queries
│   ├── ingested_message.py   # Raw ingested message state model
│   ├── institution.py        # Tenant workspace model
│   ├── user.py               # User authentication & RBAC model
│   └── model_registry.py     # ML model registry & persistence
├── routes/
│   ├── admin.py              # SOC administrative decision & warning APIs
│   ├── analysis.py           # Threat analysis intake & dispatch APIs
│   ├── auth.py               # Authentication, registration & session routes
│   ├── email_integration.py  # Mailbox configuration & sync endpoints
│   └── models.py             # Model Studio retraining & evaluation APIs
├── services/
│   ├── bullying_detector.py  # Hybrid TF-IDF NLP cyberbullying engine
│   ├── phishing_detector.py  # Phishing, URL entropy & typosquatting engine
│   ├── social_eng_detector.py# Social engineering intent detector
│   ├── attachment_analyzer.py# Static binary attachment malware analyzer
│   ├── image_forensics.py    # Passive EXIF metadata & image forensic analyzer
│   ├── risk_engine.py        # Unified multi-vector risk aggregation engine
│   ├── imap_client.py        # Secure IMAP SSL client with delta UID tracking
│   ├── mime_parser.py        # Memory-safe streaming RFC 822 MIME parser
│   ├── crypto_service.py     # Fernet AES-128 credential encryption service
│   ├── auth_email_service.py # Transactional SMTP notification dispatcher
│   ├── email_service.py      # Mailbox management & atomic sync lease coordinator
│   ├── llm_threat_analyzer.py# Optional AI/LLM threat evaluation service
│   └── rate_limiter.py       # Sliding-window token bucket rate limiter
├── worker/
│   ├── daemon.py             # Autonomous background polling daemon
│   └── processor.py          # Mailbox processor with lease enforcement
static/
├── css/                      # Dark SOC & Light theme stylesheets
└── js/                       # Dashboard telemetry, stream renderer & charts
templates/                    # Jinja2 HTML dashboard & authentication views
tests/                        # 256 automated pytest test suites
```

---

## 11. Future Enhancements

- **Graph-Based Threat Correlation:** Temporal correlation of multi-stage attack campaigns across multiple senders and recipient clusters.
- **Automated SOC Remediation Playbooks:** Configurable webhook triggers to automatically quarantine high-risk senders in upstream institutional mail gateways.
- **Comparative AI Reasoning:** Extended benchmarking of zero-shot large language models alongside lightweight supervised linear models.

---

## 12. License & Academic Disclaimer

BullyMail is developed for academic research and defensive cybersecurity operations. It enforces zero-execution static analysis and strict in-memory parsing to ensure safe forensic evaluation of untrusted data.
