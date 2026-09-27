# BullyMail — Threat Intelligence & Cyberbullying Detection Platform

[![Live Demo](https://img.shields.io/badge/Live_Demo-Render_Cloud-46E3B7?style=for-the-badge&logo=render&logoColor=white)](https://bullymail-threat-intelligence.onrender.com)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Framework: Flask](https://img.shields.io/badge/Framework-Flask_3.x-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Tests Passing](https://img.shields.io/badge/Tests-362_Passed-brightgreen?style=for-the-badge&logo=pytest&logoColor=white)]()
[![Security: AES-128 & RBAC](https://img.shields.io/badge/Security-Fernet_AES--128_%7C_RBAC-critical?style=for-the-badge)]()

> 🌐 **Live Platform URL:** [https://bullymail-threat-intelligence.onrender.com](https://bullymail-threat-intelligence.onrender.com)

BullyMail is an enterprise digital forensic email threat intelligence and cyberbullying detection platform engineered for educational institutions and organizations. It automatically ingests communications, evaluates multi-vector threat surfaces, performs hybrid linguistic machine learning with forensic signal analysis, and provides explainable risk scoring through an interactive Security Operations Center (SOC) dashboard.

---

## 🎯 Key Capabilities

* 🛡️ **Multi-Vector Threat Decomposition:**
  * **Linguistic Cyberbullying Engine:** TF-IDF feature extraction combined with calibrated Machine Learning classification (Logistic Regression / Linear SVC) and deterministic violence/harassment rule overrides.
  * **Phishing & Brand Spoofing Detector:** Normalized Levenshtein distance typosquatting analysis, Shannon URL entropy scoring, and deep credential-stealing parameter inspection.
  * **Social Engineering Detector:** Flags artificial urgency triggers (*"immediate action required"*), authority impersonation, and extortion patterns.
  * **Static Attachment Forensics:** Zero-execution in-memory binary analysis, magic byte verification (`MZ`, `ELF`), double-extension cloaking detection, and EXIF metadata extraction.
* 📊 **Interactive SOC Dashboard:** Real-time posture assessment, severity distribution (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), velocity trend charts, and an incident ledger.
* 🏢 **Multi-Tenant RBAC:** Complete data isolation across institutions with fine-grained roles (`platform_owner`, `org_admin`, `analyst`).
* ⚠️ **Incident Warning Workflow:** Cloud-native warning email dispatch over HTTPS with verified sender fallback and reply-to routing.
* 🔒 **Zero-Trust Security:** Master-key credential encryption (AES-128 Fernet), CSRF protection, OWASP security response headers, and audit trails.

---

## 🏗️ Architecture & Pipeline Flow

```text
┌────────────────────────────────────────────────────────────────────────┐
│  📨 Ingestion Layer: IMAP SSL (Automated) • Raw Upload • Direct Intake │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│  🔍 SafeMIMEParser: RFC 822 Decomposition & In-Memory Stream Processing│
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      ⚙️ Unified Forensic Risk Engine                    │
├───────────────────────────────────┬────────────────────────────────────┤
│ • NLP Cyberbullying Detection     │ • Phishing & Typosquatting Analysis│
│   (TF-IDF + Logistic Regression)  │   (Levenshtein + Shannon Entropy)  │
├───────────────────────────────────┼────────────────────────────────────┤
│ • Social Engineering Heuristics   │ • Static Attachment & Image Scan   │
│   (Urgency & Impersonation)       │   (Magic Bytes + EXIF Metadata)    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│  📊 Risk Aggregator: Multi-Vector Calibrated Threat Score [0.0 - 1.0]  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│  🖥️ SOC Dashboard • Multi-Tenant RBAC • Verified Warning Dispatch      │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quickstart

### Prerequisites
* Python 3.10+
* Git

### Local Setup in 3 Steps

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/jayachandra2003/BullyMail-Threat-Intelligence.git
   cd BullyMail-Threat-Intelligence
   ```

2. **Create a Virtual Environment & Install Dependencies:**
   ```bash
   python -m venv venv
   # Linux / macOS:
   source venv/bin/activate
   # Windows:
   venv\Scripts\activate

   pip install -r requirements.txt
   ```

3. **Launch BullyMail:**
   ```bash
   python app.py
   ```
   Open [http://localhost:5000](http://localhost:5000) in your browser.

---

## 🚢 Production Deployment

* **Production WSGI (Waitress - Windows):**
  ```bash
  python wsgi.py
  ```
* **Production WSGI (Gunicorn - Linux / Render):**
  ```bash
  gunicorn --workers 1 --threads 2 --bind 0.0.0.0:$PORT wsgi:app
  ```
* **Docker Container:**
  ```bash
  docker-compose up -d
  ```

---

## 🧪 Automated Testing

BullyMail includes a comprehensive test suite covering detection engines, authentication, multi-tenancy, and cloud API dispatches:

```bash
pytest tests/
```
```text
======================= 362 passed, 1 skipped in 232.27s =======================
```

---

## 📚 Technical Documentation Hub

For in-depth architectural and operational guides, visit the [`docs/`](docs/) directory:

* 📐 [System Architecture & Data Flow](docs/ARCHITECTURE.md)
* 📡 [REST API Documentation](docs/API_DOCUMENTATION.md)
* 🧠 [Machine Learning & Forensic Methodology](docs/ML_METHODOLOGY.md)
* ☁️ [Render Cloud Deployment Guide](docs/DEPLOYMENT_RENDER.md)
* 🏛️ [Oracle Cloud Always-Free Deployment Guide](docs/DEPLOYMENT_ORACLE.md)
* 🔐 [Security Architecture & Encryption Model](docs/SECURITY.md)

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
