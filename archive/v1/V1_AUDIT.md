# BullyMail V1 — Comprehensive Project Audit Report

**Date:** August 2026  
**Auditor:** Lead Software Architect & Senior Full-Stack / ML Engineer  
**Project:** BullyMail – Intelligent Email Bullying, Phishing, and Security Threat Detection System  

---

## Executive Summary

BullyMail V1 provides a proof-of-concept foundation for cyberbullying detection in academic emails using TF-IDF vectorization, simple classification models (Logistic Regression, Linear SVM), and rule-based keyword matching. However, the existing V1 implementation suffers from architectural monolithism, severe security vulnerabilities, lack of multi-threat detection (no phishing, link analysis, malware scanning, social engineering detection, or image forensics), hardcoded credentials, synthetic metric distortion (artificial 100% scores), and unscalable synchronous execution.

This audit evaluates the codebase across 10 critical dimensions to guide the transition into a production-grade **BullyMail V2**.

---

## 1. What Already Works (V1 Strengths to Preserve)

- **End-to-End Cyberbullying Pipeline:** Functional TF-IDF text vectorization (`ngram_range=(1,2)`, `max_features=2000`) paired with Logistic Regression and Support Vector Machines (Linear SVC).
- **Rule-Based & Hybrid Scoring Logic:** Academic bullying phrase dictionary combined with ML probability estimates (`0.4 * rule_score + 0.6 * ml_prob`).
- **Model Serialization & Loading:** Persistence of vectorizer and model artifacts via `joblib` in `saved_models/`.
- **IMAP / SMTP Integration:** Fetching email headers and RFC822 bodies from mail servers with TLS support.
- **Dataset Synthesis:** Automated generation of academic email samples with diverse roles (Professor, Advisor, Student) and subjects.
- **Web UI & Authentication Shell:** Flask application routes for landing page, admin login, live demo, and dashboard tabs.

---

## 2. What Is Broken / Malfunctioning

- **Invalid `requirements.txt` Syntax:** Every line contains `pip install <package>` instead of standard `<package>==<version>`, breaking `pip install -r requirements.txt`.
- **Hardcoded Database Credentials:** `Config.DB_CONFIG` contains hardcoded password (`JChandra@2003`), causing immediate failure in standard environments without that specific setup.
- **Hardcoded Admin Authentication:** `/login` directly matches strings `'admin'` and `'admin123'` in Python code rather than querying the `users` table or verifying hashes.
- **Rule-Based Score Normalization Flaw:** `len(matches) / len(BULLYING_PHRASES)` produces extremely deflated scores (e.g. 1 match out of 40 yields 0.025), rendering the rule-based weight ineffective.
- **In-Memory Email Credentials:** Credentials in `EmailIntegration` reside only in memory and are lost on restart.
- **Broken Drill-Down in UI:** Analysis history "View Details" button triggers a placeholder alert (`alert('Viewing analysis details...')`) rather than rendering actual report data.
- **Synchronous Large Request Blocking:** Dataset generation (up to 50k samples) runs synchronously inside HTTP requests, triggering gateway timeouts.

---

## 3. What Is Poorly Designed

- **Monolithic Backend (`app.py`):** 1,488 lines containing DB configuration, ML models, text processing, email transport, dataset generators, and HTTP route handlers in a single file.
- **Monolithic Frontend (`dashboard.html`):** 1,632 lines containing combined HTML markup, styling, and ~1,000 lines of unmodular JavaScript.
- **Ephemeral Session Secret:** `app.secret_key = secrets.token_hex(16)` regenerates on every server startup, abruptly terminating all user sessions.
- **Lack of Layered Architecture:** Missing repository layer, service layer, Blueprint routing, and centralized configuration management.

---

## 4. Security Vulnerabilities

- **CWE-259 / CWE-798 (Hardcoded Secrets):** Database passwords and default credentials committed to source.
- **CWE-256 (Plaintext Password Storage):** `users` table stores passwords as plain text without hashing (e.g., PBKDF2 / Argon2 / bcrypt / Werkzeug security).
- **CWE-352 (Missing CSRF Protection):** No CSRF protection on POST forms and API endpoints.
- **CWE-434 (Unsafe File Upload & Static Analysis Risks):** No file upload validation, MIME sniffing, double-extension inspection, or attachment sandboxing.
- **CWE-942 (Permissive CORS):** Unrestricted `CORS(app)` without origin whitelisting.
- **Insecure Cookies:** Session cookies lack `HttpOnly`, `SameSite`, and `Secure` flags.

---

## 5. Machine Learning Weaknesses

- **Synthetic Overfitting & Metric Distortion:** 100% precision, recall, and accuracy in `model_history` caused by training and testing on templated synthetic phrases with zero real-world noise.
- **Missing Threat Detection Capabilities:**
  - No Phishing Detection (urgency, credential theft, domain spoofing).
  - No URL / Link Security Analysis (IP URLs, punycode, obfuscation, look-alike domains).
  - No Social Engineering Detection (intimidation, authority abuse, financial manipulation).
  - No Malware / Attachment Static Analysis (double extensions, script detection, macro checks).
  - No Image Forensics (ELA, metadata, EXIF, manipulation analysis).
- **No Explainable AI (XAI):** Predictions are returned as black-box numbers without token contribution, feature importance, or interpretable threat evidence.
- **Missing Visual Evaluation:** No confusion matrices, ROC/PR curves, or cross-validation reporting.

---

## 6. Database Weaknesses

- **Legacy Latin1 Encoding:** Schema created with `DEFAULT CHARACTER SET latin1`, which mangles emojis, multilingual text, and special obfuscation characters.
- **Inflexible Schema:** `analyzed_emails` only stores bullying flags and lacks fields for phishing, URLs, social engineering, attachments, image forensics, unified risk scores, and evidence breakdown.
- **Missing Indexes & Foreign Keys:** No indexing on `created_at`, `email_from`, `is_bullying`, or `risk_level`.
- **Ad-hoc Connection Management:** Opening and closing raw MySQL connections per route without connection pooling or SQLite fallback for portable local development.

---

## 7. UI / UX Weaknesses

- **Lack of Unified Threat Visualization:** Dashboard displays only basic bullying counts and lacks threat level breakdowns (LOW/MEDIUM/HIGH/CRITICAL), confidence distributions, and radar/bar charts.
- **No Multi-Input Analysis Interface:** Analysis tab only takes email text; lacks inputs for sender email verification, attachment upload, image inspection, and extracted URL lists.
- **No Exportable Reports:** Missing PDF generation and Excel/CSV threat report export.
- **Basic History Table:** No pagination, full-text search, threat-level filtering, or detailed modal inspections.

---

## 8. Performance & Scalability Problems

- **No Connection Pooling:** Each request creates a new TCP socket connection to MySQL.
- **Synchronous Heavy Tasks:** Model training and batch analysis lock the web worker.
- **Unoptimized Static Assets:** Uncompressed background images (>2.8MB).

---

## 9. Code Duplication

- Duplicate phrase matching logic in both `app.py` and client-side JavaScript (`index.html`).
- Repetitive DB connection boilerplate across all route endpoints.
- Redundant dataset generation logic between quick and large generation methods.

---

## 10. Architectural Deficiencies

- High coupling between Flask endpoints, database queries, and ML training code.
- Inability to extend or plug in new detection engines (e.g., URL Analyzer, Social Engineering Analyzer, Malware Scanner, Image Forensics Engine) without bloating `app.py`.
- Lack of a central **Unified Risk Engine** that aggregates multi-detector findings with transparent scoring logic.

---

## Summary Matrix: V1 vs. V2 Target

| Component | BullyMail V1 (Current) | BullyMail V2 (Target) |
| :--- | :--- | :--- |
| **Architecture** | Single 1,488-line `app.py` | Modular Blueprint & Service Layer Architecture |
| **Cyberbullying** | Synthetic 100% Overfit TF-IDF | Enhanced Hybrid (Realistic evaluation, explainable terms, metrics) |
| **Phishing Analysis** | ❌ None | ✅ Suspicious language, credential harvesting, urgent intent, domain checks |
| **URL Security** | ❌ None | ✅ Safe/Suspicious/High-Risk/Malicious classification, look-alike domain detection |
| **Social Engineering** | ❌ None | ✅ Authority, urgency, fear, reward manipulation, financial pressure detection |
| **Malware / Attachments** | ❌ None | ✅ Safe static analysis (hashes, MIME, double extensions, macro/script checks) |
| **Image Forensics** | ❌ None | ✅ Metadata/EXIF inspection, ELA / compression artifact analysis |
| **Unified Risk Engine** | ❌ None | ✅ Multi-detector aggregator (LOW/MED/HIGH/CRITICAL + Confidence + Evidence) |
| **Explainable AI (XAI)** | ❌ None | ✅ Feature importance, token contributions, transparent reasoning |
| **Database** | Latin1 MySQL only, basic schema | UTF-8 / utf8mb4, SQLite / MySQL dual support, rich threat schema |
| **Security** | Plaintext credentials, no CSRF/limits | Password hashing (Werkzeug), `.env` config, CSRF, input validation |
| **Reports** | ❌ None | ✅ Professional PDF reports and CSV exports |
| **Testing** | ❌ None | ✅ Pytest suite covering all detectors, API routes, and edge cases |
