# BullyMail Threat Intelligence Platform — Render Free Tier Deployment Guide

This guide provides step-by-step instructions for deploying the **BullyMail V2 Threat Intelligence Platform** on the **Render Free Tier** to create a live, publicly accessible portfolio/demo URL.

---

## 🛑 STRICT COST SAFETY NOTICE

> **"This deployment is intended for the Render Free tier. Do not select paid resources or paid services."**

### Free-Tier vs. Paid Trap Awareness:
* **Selected Web Service Plan**: Select **"Free"** ($0/month).
* **Selected Database**: We use BullyMail's **embedded SQLite engine** (`DB_TYPE=sqlite`). Do **NOT** select Render's managed PostgreSQL database (Render's free PostgreSQL expires after 90 days or incurs charges if upgraded).
* **Selected Add-ons**: Do **NOT** add paid Redis, worker instances, or custom domain paid features.
* **Credit Card Verification**: Render Free Web Services do **NOT** require a credit card to launch.

---

## 🔒 SECURITY & SECRET MANAGEMENT

> ⚠️ **CRITICAL SECURITY REQUIREMENT**:
> NEVER commit `.env` files, API keys, passwords, or Fernet master keys to Git or GitHub.
> All sensitive configuration must be entered directly into **Render Dashboard → Environment Variables**.
> Any previously displayed example key or token must be treated as exposed and **NEVER** reused.

### Generating Fresh Production Keys Locally:
Run the following commands in your local terminal to generate fresh, cryptographically secure keys before configuring Render:

1. **Generate `SECRET_KEY`**:
   ```bash
   python -c "import secrets; print(secrets.token_hex(32))"
   ```
2. **Generate `BULLYMAIL_MASTER_KEY`** (Fernet Base64 Key for credential encryption):
   ```bash
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```

---

## 📐 SERVICE ARCHITECTURE FOR RENDER FREE

| Parameter | Configuration Detail |
| :--- | :--- |
| **Service Type** | **Render Web Service** (Single Instance) |
| **Runtime Environment** | Python 3.10 or Docker |
| **Instance Plan** | **Free** (512 MB RAM, 0.1 CPU allocation) |
| **Database Engine** | Embedded SQLite (`DB_TYPE=sqlite` on persistent `/app/bullymail.db` or ephemeral container disk) |
| **Production WSGI** | Gunicorn (`gunicorn --workers 1 --threads 2 --bind 0.0.0.0:$PORT wsgi:app`) |
| **Health Check Path** | `/health` |

---

## ⚙️ RENDER CONFIGURATION OPTIONS

You can deploy BullyMail on Render using either **Native Python** or **Docker**. Option A (Native Python) is the simplest and recommended method.

### Option A: Native Python Deployment (Recommended)
* **Runtime**: `Python 3`
* **Build Command**:
  ```bash
  pip install -r requirements.txt && python -c "import nltk; nltk.download('punkt'); nltk.download('stopwords')"
  ```
* **Start Command**:
  ```bash
  gunicorn --workers 1 --threads 2 --bind 0.0.0.0:$PORT wsgi:app
  ```

---

### Option B: Docker Deployment
* **Runtime**: `Docker`
* **Dockerfile Path**: `./Dockerfile`
* **Docker Context**: `.`
* Render will automatically build the Dockerfile and pass `$PORT` to the container environment.

---

## 🔑 REQUIRED ENVIRONMENT VARIABLES

Configure the following environment variables under **Render Dashboard → Web Service & Background Worker → Environment**:

| Variable Name | Value / Description | Required / Optional |
| :--- | :--- | :--- |
| `FLASK_ENV` | `production` | **Required** |
| `SECRET_KEY` | `<GENERATE_A_RANDOM_SECRET>` | **Required** |
| `ADMIN_PASSWORD` | `<CHOOSE_YOUR_ADMIN_PASSWORD>` | **Required** |
| `DATABASE_URL` | `mysql://user:pass@host:3306/dbname` or `postgres://user:pass@host:5432/dbname` | **Recommended for Persistence** |
| `DB_TYPE` | `mysql` or `postgres` (Auto-detected if `DATABASE_URL` or `DB_HOST` is set) | **Required if not using `DATABASE_URL`** |
| `DB_HOST` | Database Host address (e.g., `mysql.railway.internal` or Aiven/PlanetScale host) | Required for explicit DB config |
| `DB_USER` | Database Username | Required for explicit DB config |
| `DB_PASSWORD` | Database Password | Required for explicit DB config |
| `DB_NAME` | Database Name (e.g., `bullymail_db`) | Required for explicit DB config |
| `BULLYMAIL_MASTER_KEY` | `<GENERATE_A_FERNET_KEY>` | **Required for Mailbox Encrypted Password Storage** |
| `ADMIN_USERNAME` | `admin` *(default)* | Optional |
| `ADMIN_EMAIL` | `admin@bullymail.local` | Optional |

> ⚠️ **PERSISTENCE REQUIREMENT**:
> Container local filesystems on Render Free are ephemeral and reset when services cold-start or restart.
> To persist mailboxes, analyzed emails, threat records, and user data across restarts, set `DATABASE_URL` or `DB_HOST`/`DB_USER`/`DB_PASSWORD`/`DB_NAME` pointing to a persistent MySQL or PostgreSQL database.
> Make sure both your **Web Service** and **Background Worker** use the **EXACT SAME `DATABASE_URL` / Database configuration**.

---

## 🚀 STEP-BY-STEP DEPLOYMENT PROCEDURE

### Step 1: Create a Render Account
1. Go to [https://render.com](https://render.com) and sign up for a free account using your GitHub account.

### Step 2: Connect GitHub Repository
1. In the Render Dashboard, click **New +** → Select **Web Service**.
2. Connect your GitHub repository:
   `https://github.com/jayachandra2003/BullyMail-Threat-Intelligence`
3. Give your web service a unique name (e.g., `bullymail-demo` or `bullymail-threat-intel`).

### Step 3: Configure Instance & Build Settings
1. **Region**: Select the region closest to you (e.g., Oregon, Frankfurt, Singapore).
2. **Branch**: `main`
3. **Runtime**: Select `Python 3` (or `Docker`).
4. **Build Command**:
   ```bash
   pip install -r requirements.txt && python -c "import nltk; nltk.download('punkt'); nltk.download('stopwords')"
   ```
5. **Start Command**:
   ```bash
   gunicorn --workers 1 --threads 2 --bind 0.0.0.0:$PORT wsgi:app
   ```
6. **Instance Type**: Select **Free** ($0/month).

### Step 4: Add Environment Variables
1. Scroll down to **Advanced** → **Environment Variables**.
2. Add the required variables:
   * `FLASK_ENV` = `production`
   * `SECRET_KEY` = `<YOUR_GENERATED_SECRET_KEY>`
   * `ADMIN_PASSWORD` = `<YOUR_CHOSEN_ADMIN_PASSWORD>`
   * `DB_TYPE` = `sqlite`
   * `BULLYMAIL_MASTER_KEY` = `<YOUR_GENERATED_FERNET_KEY>`
3. Set **Health Check Path** to: `/health`

### Step 5: Deploy Web Service
1. Click **Create Web Service**.
2. Render will trigger the build pipeline (installing packages, downloading NLTK datasets, initializing Flask WSGI).
3. Once built, Render will display: `Your service is live 🎉` and provide your public URL:
   `https://bullymail-demo.onrender.com`

---

## 🧪 TESTING & VERIFICATION STEPS

After deployment completes:

1. **Verify Health Endpoint**:
   Open `https://<YOUR_RENDER_URL>/health` in your browser.
   It should return: `{"service": "BullyMail Threat Intelligence Platform", "status": "ok"}`
2. **Verify Public UI**:
   Open `https://<YOUR_RENDER_URL>` to access the BullyMail landing page.
3. **Verify Authentication**:
   Go to `/login` and log in with:
   * **Username**: `admin`
   * **Password**: *(The `ADMIN_PASSWORD` set in environment variables)*
4. **Verify Quick Demo Threat Analysis**:
   On the homepage or dashboard, enter a sample threat (e.g., `I will hurt you badly if you do not comply`) and click **Analyze**. Verify that risk scoring and explainable evidence render cleanly.

---

## ⚠️ RENDER FREE-TIER LIMITATIONS & CHARACTERISTICS

1. **Inactivity Spin-Down**:
   Render Free web services spin down after **15 minutes of inactivity**. The first request after spin-down will take **30–50 seconds** to wake up (cold start). Subsequent requests respond instantly.
2. **512 MB Memory Limit**:
   BullyMail is configured to run 1 Gunicorn worker with 2 threads, consuming only ~120 MB RAM. This leaves >350 MB RAM buffer.
3. **Ephemeral SQLite Disk**:
   Files created on Render Free's local filesystem reset when the container restarts. The initial database, threat taxonomy rules, and ML models re-initialize automatically on startup via `init_db()`.

---

## 🔍 TROUBLESHOOTING

| Problem | Root Cause | Solution |
| :--- | :--- | :--- |
| **500 Server Error on Startup** | Missing `SECRET_KEY` or `ADMIN_PASSWORD` in production mode | Ensure both variables are defined in the Render Environment tab. |
| **Build Timeout / Out of Memory** | Multiple Gunicorn workers allocated | Ensure start command uses `--workers 1 --threads 2`. |
| **NLTK Resource Not Found** | NLTK stopwords/punkt not installed during build | Verify build command includes `python -c "import nltk; nltk.download('punkt'); nltk.download('stopwords')"`. |
| **Model Load Error** | Path resolution issue | Models reside in `saved_models/` and load automatically via `joblib`. |
