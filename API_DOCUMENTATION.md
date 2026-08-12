# BullyMail V2 — REST API Documentation

This document describes the API endpoints provided by BullyMail V2 for integration with external security tools, mail relays, and frontends.

---

## 1. Authentication Endpoints

### `POST /login`
Authenticates a user and establishes an HTTP session.
- **Request Body (JSON or Form):**
  ```json
  {
    "username": "admin",
    "password": "admin123"
  }
  ```
- **Response (200 OK):**
  ```json
  {
    "success": true,
    "message": "Login successful",
    "redirect": "/dashboard"
  }
  ```

### `GET /logout`
Terminates the current user session and redirects to `/`.

---

## 2. Threat Analysis Endpoints

### `POST /api/analyze-email` *(Authenticated)*
Performs comprehensive multi-vector analysis on an email. Supports JSON payload or `multipart/form-data` with attachments and images.

- **Request Body (JSON):**
  ```json
  {
    "email_subject": "Urgent Security Notice",
    "email_from": "IT Support <support@paypa1.com>",
    "email_to": "student@university.edu",
    "email_text": "Verify your credentials at http://paypa1.com/login within 24 hours."
  }
  ```
- **Response (200 OK):**
  ```json
  {
    "success": true,
    "report": {
      "id": 1,
      "email_subject": "Urgent Security Notice",
      "overall_risk_level": "HIGH",
      "overall_confidence": 0.88,
      "threat_score": 0.85,
      "bullying_analysis": {
        "is_bullying": false,
        "confidence": 0.0
      },
      "phishing_analysis": {
        "risk_level": "HIGH",
        "confidence": 0.82,
        "indicators": [...]
      },
      "url_analysis": {
        "total_urls": 1,
        "suspicious_count": 1,
        "urls": [...]
      },
      "domain_analysis": {
        "is_suspicious": true,
        "impersonated_brand": "PayPal"
      },
      "evidence": [
        {
          "category": "Domain Impersonation",
          "severity": "HIGH",
          "title": "Potential Look-Alike Domain: paypa1.com",
          "details": "Domain mimics PayPal using character substitution."
        }
      ]
    }
  }
  ```

### `POST /api/quick-demo-analyze` *(Public)*
Lightweight public endpoint for the landing page interactive demo.

---

## 3. Executive Dashboard & History Endpoints

### `GET /api/system-stats` *(Authenticated)*
Returns aggregate threat intelligence statistics and risk distribution counts.

### `GET /api/analysis-history` *(Authenticated)*
- **Query Parameters:**
  - `limit` (int, default: 50)
  - `risk` (string: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
  - `search` (string: keyword search across subject/sender/text)

### `GET /api/reports/view/<analysis_id>` *(Authenticated)*
Renders a standalone printable HTML security audit report.

### `GET /api/reports/download-csv` *(Authenticated)*
Downloads a CSV export of past threat analyses.

---

## 4. Model Studio Endpoints

### `GET /api/model-status` *(Authenticated)*
Retrieves current model status, active classifier type, and past training runs with confusion matrices.

### `POST /api/train-model` *(Authenticated)*
Trains a new classifier and calculates evaluation metrics.
- **Request Body:**
  ```json
  {
    "model_type": "logistic",
    "training_samples": 2000
  }
  ```
- **Response:**
  ```json
  {
    "success": true,
    "results": {
      "model_type": "Logistic Regression",
      "accuracy": 0.98,
      "precision": 0.97,
      "recall": 0.99,
      "f1_score": 0.98,
      "confusion_matrix": [[245, 5], [2, 248]],
      "test_samples": 500
    }
  }
  ```
