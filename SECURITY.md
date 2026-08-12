# BullyMail V2 — Security Policy & Safe Analysis Protocol

## 1. Security Architecture & Threat Model

BullyMail V2 handles potentially hostile and untrusted email content, attachments, and links. The following security controls are strictly enforced:

### Zero Execution Guarantee (Malware Analysis)
- **Static Analysis Only:** Uploaded attachments and embedded files are **never executed**, spawned into subprocesses, or rendered by active engines.
- Inspection is strictly limited to static binary signature analysis (PE/MZ magic headers), filename/extension validation, macro string extraction, and cryptographic hashing (MD5, SHA-256).

### Safe URL Inspection Protocol
- **No Automatic Network Fetching:** Extracted URLs are **never automatically browsed or requested over HTTP/HTTPS** during automated scans.
- Analysis is performed via passive lexical decomposition: IP detection, punycode parsing, domain distance algorithms, and known URL shortener classification.

### Password Security & Session Management
- Passwords are encrypted using **Werkzeug's PBKDF2/SHA256** key derivation with individual salts.
- Plaintext passwords are never logged or stored.
- Session cookies are configured with `HttpOnly=True` and `SameSite=Lax` to mitigate XSS and CSRF session hijacking.

### Secret Management
- Database credentials, secret keys, and email passwords are removed from source code and read from environment variables (`.env`).
- `.env` is excluded from version control via `.gitignore`.

---

## 2. File Upload Restrictions

- **Maximum Upload Size:** 16 MB (`MAX_CONTENT_LENGTH`).
- **Filename Sanitization:** All incoming filenames are normalized using `werkzeug.utils.secure_filename`.
- **Double Extension Detection:** Files attempting to disguise executables as documents (e.g., `document.pdf.exe`) are immediately flagged as `MALICIOUS`.
