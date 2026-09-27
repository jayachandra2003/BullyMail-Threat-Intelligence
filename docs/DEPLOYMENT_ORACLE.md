# BullyMail Threat Intelligence Platform — Oracle Cloud Always Free Deployment Guide

This guide provides an exact step-by-step procedure for deploying the **BullyMail V2 Threat Intelligence Platform** on **Oracle Cloud Infrastructure (OCI) Always Free Tier** at **STRICTLY ₹0 COST**.

> **Target Configuration Notice**:
> For this project, the deployment target is 2 OCPUs + 12 GB RAM on VM.Standard.A1.Flex. We intentionally stay within the Always Free resource allocation and do not depend on paid resources.

---

## 🛑 ₹0 COST SAFETY & RESOURCE LIMITS

To guarantee that your deployment remains **100% FREE forever (₹0 cost)** and never incurs accidental cloud billing, follow these strict rules:

1. **Use ONLY "Always Free Eligible" Resources**:
   * Always look for the grey/green **"Always Free Eligible"** badge next to shapes and images in the Oracle Cloud Console.
2. **Target Shape: Ampere A1 (ARM64)**:
   * **Shape**: `VM.Standard.A1.Flex`
   * **Target Capacity**: Exactly **2 OCPUs and 12 GB RAM** for our strict ₹0 deployment plan (guaranteeing zero charges while providing optimal performance for scikit-learn and MySQL).
3. **DO NOT Upgrade to "Pay As You Go"**:
   * Keep your account in the free tier status. Do not enable automatic credit card billing or paid tier conversion.
4. **Boot Volume Quota**:
   * Set boot volume size to **50 GB** (Oracle grants 200 GB total boot storage free across your tenancy). Do not exceed 200 GB.
5. **Zero Paid Managed Services**:
   * **No Paid Managed Database**: We run MySQL 8.0 inside Docker on the VM at ₹0.
   * **No Paid Load Balancer**: We run Nginx as a reverse proxy directly on the VM at ₹0.
   * **No Paid SSL Certificates**: We use Let's Encrypt (Certbot) for free automated SSL at ₹0.
   * **No Paid Object Storage / GPU**: All ML models and datasets reside on the VM's local SSD volume at ₹0.
6. **Egress Bandwidth**:
   * Oracle provides **10 TB/month of free outbound data transfer**. BullyMail's typical usage is under 5 GB/month.

---

## STEP-BY-STEP DEPLOYMENT PROCESS

### Section A: Create Oracle Always Free VM
1. Log in to [Oracle Cloud Console](https://cloud.oracle.com).
2. Open the navigation menu (top-left hamburger icon) → **Compute** → **Instances**.
3. Click **Create Instance**.
4. Set the name to: `bullymail-server`.
5. Under **Placement**, leave the default Availability Domain selected.

---

### Section B: Select ARM64 A1 & Operating System
1. In the **Image and shape** section, click **Edit Image**.
   * Select **Canonical Ubuntu**.
   * Choose **Ubuntu 22.04 LTS Minimal** or **Ubuntu 22.04 LTS** (ARM64).
2. Click **Edit Shape**.
   * Click **Change Shape**.
   * Shape series: Select **Ampere**.
   * Choose **`VM.Standard.A1.Flex`** (marked with **Always Free Eligible**).

---

### Section C: Configure 2 OCPUs / 12 GB RAM
1. Under the `VM.Standard.A1.Flex` sliders:
   * Set **Number of OCPUs**: `2`
   * Set **Amount of memory (GB)**: `12`
2. Under **Boot volume**:
   * Check **Specify a custom boot volume size**.
   * Enter: `50` GB (Always Free allows up to 200 GB).

---

### Section D: Configure SSH Key Pair
1. Under **Add SSH keys**:
   * Select **Generate a key pair for me** → Click **Save private key** (`.key`) and **Save public key**. Store the private key securely on your local computer.
   * *(Alternatively, paste your existing public SSH key if you already have one).*
2. Under **Networking**:
   * Choose **Create new virtual cloud network** (or select your existing VCN).
   * Ensure **Assign a public IPv4 address** is set to **Yes**.
3. Click **Create** at the bottom.
4. Wait 1–2 minutes until the instance status changes from *Provisioning* to a green **Running** state. Note your **Public IP Address** (e.g., `129.153.xx.xx`).

---

### Section E: Configure Oracle & OS Firewalls

#### 1. Oracle Cloud Virtual Cloud Network (VCN) Security List
Only three public ingress ports are permitted:
* Navigate to **Networking** → **Virtual Cloud Networks** → Click your VCN → Click your **Public Subnet** → Click **Default Security List for...**.
* Click **Add Ingress Rules** and add:

| Source CIDR | IP Protocol | Destination Port | Purpose |
| :--- | :--- | :--- | :--- |
| `0.0.0.0/0` | TCP | `22` | SSH Administration |
| `0.0.0.0/0` | TCP | `80` | HTTP / ACME Let's Encrypt |
| `0.0.0.0/0` | TCP | `443` | HTTPS Encrypted Web |

> 🔒 **Security Notice**: DO NOT open port 3306 (MySQL) or 5000 (Flask). They must remain completely inaccessible from the public internet.

#### 2. Connect via SSH
From your local terminal (PowerShell or Bash):
```bash
ssh -i /path/to/your-private-key.key ubuntu@<YOUR_PUBLIC_IP>
```

#### 3. Configure Ubuntu OS-Level Firewall
Oracle Ubuntu cloud images have default iptables rules blocking ports 80 and 443. Open them with:
```bash
# Allow HTTP and HTTPS in host iptables
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 443 -j ACCEPT

# Save iptables rules to persist across reboots
sudo apt update && sudo apt install -y iptables-persistent netfilter-persistent
sudo netfilter-persistent save
```

---

### Section F: Install Docker & Docker Compose
Install the official Docker engine and reverse proxy packages:
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl git nginx certbot python3-certbot-nginx

# Install Docker engine
curl -fsSL https://get.docker.com | sh

# Grant docker permissions to ubuntu user
sudo usermod -aG docker ubuntu

# Apply docker group without logging out
newgrp docker

# Verify installations
docker --version
docker compose version
```

---

### Section G: Clone GitHub Repository
Clone the repository to the home directory:
```bash
cd /home/ubuntu
git clone https://github.com/jayachandra2003/BullyMail-Threat-Intelligence.git bullymail
cd bullymail
```

---

### Section H: Configure `.env` Securely

> ⚠️ **SECURITY MANDATE**: Never commit `.env` to Git. Create it only on the live server.

Create `.env`:
```bash
nano .env
```

Generate secure cryptographic keys on the VM:
```bash
# Generate SECRET_KEY:
python3 -c "import secrets; print(secrets.token_hex(32))"

# Generate BULLYMAIL_MASTER_KEY:
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Fill in your `.env` configuration file:
```ini
# Flask Core
FLASK_ENV=production
FLASK_DEBUG=False
PORT=5000
HOST=0.0.0.0
APP_BASE_URL=https://your-domain-or-ip.nip.io

# Cryptographic Keys (Generated above)
SECRET_KEY=paste_64_character_hex_secret_here
BULLYMAIL_MASTER_KEY=paste_32_byte_fernet_base64_key_here

# Database Configuration (Internal Docker Network)
DB_TYPE=mysql
DB_HOST=db
DB_PORT=3306
DB_NAME=bullymail_db
DB_USER=bullymail_user
DB_PASSWORD=SetAStrongRandomDbPasswordHere
MYSQL_ROOT_PASSWORD=SetAStrongRandomRootPasswordHere

# Admin User Account
ADMIN_USERNAME=admin
ADMIN_PASSWORD=SetAStrongAdministratorPassword123!
ADMIN_EMAIL=admin@bullymail.local

# External AI Threat Analyzer (Optional, transient only)
OPENROUTER_API_KEY=sk-or-v1-your-key-here

# HTTPS Cookie Security
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_SAMESITE=Lax
PERMANENT_SESSION_LIFETIME=86400
```

Lock `.env` file permissions:
```bash
chmod 600 .env
```

---

### Section I: Build and Start Docker Compose
Start all services (Flask app, MySQL, and background worker):
```bash
docker compose up -d --build
```

Verify that all three services are running:
```bash
docker compose ps
```
You should see:
* `bullymail_db` (Up, healthy)
* `bullymail_app` (Up, listening on `127.0.0.1:5000`)
* `bullymail_worker` (Up, background ingestion)

Check initial application logs:
```bash
docker compose logs web
```
Confirm:
* Connected to MySQL database `bullymail_db`
* Schema migrations applied successfully
* ML models loaded from `saved_models/latest_model.joblib`

---

### Section J: Configure Nginx Reverse Proxy
Nginx receives external traffic on ports 80 and 443 and securely forwards requests to `127.0.0.1:5000`.

Determine your domain name:
* If you have a custom domain: `bullymail.yourdomain.com` (point DNS A record to your VM public IP).
* If you do not have a custom domain, use free wildcard DNS `nip.io`:
  `YOUR_IP.nip.io` (e.g., `129.153.45.67.nip.io`).

Create the Nginx configuration:
```bash
sudo nano /etc/nginx/sites-available/bullymail
```

Paste:
```nginx
server {
    listen 80;
    server_name 129.153.45.67.nip.io; # Replace with your domain or nip.io address

    client_max_body_size 20M;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Generous timeout for Model Studio training jobs
        proxy_read_timeout 180s;
        proxy_connect_timeout 60s;
        proxy_send_timeout 180s;
    }
}
```

Enable the site configuration:
```bash
sudo ln -s /etc/nginx/sites-available/bullymail /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl reload nginx
```

---

### Section K: Configure Free HTTPS (Let's Encrypt / Certbot)
Issue a free SSL certificate with automated Nginx integration:
```bash
sudo certbot --nginx -d 129.153.45.67.nip.io
```
Certbot will obtain the certificate, configure HTTPS on port 443, and set up HTTP-to-HTTPS redirection.

Verify automatic renewal:
```bash
sudo certbot renew --dry-run
```

---

### Section L: Test the Website
Open your browser and navigate to:
```text
https://<YOUR_DOMAIN_OR_NIP_IO>
```
1. Verify the landing page and security dashboard load with valid HTTPS padlock.
2. Log in using `ADMIN_USERNAME` and `ADMIN_PASSWORD` defined in `.env`.
3. Test **Threat Analyzer**: Paste a sample message and verify classification.
4. Test **Model Studio**: Verify active model status and confusion matrix display.

---

### Section M: Verify Containers & Automatic Reboot Persistence
Docker and Nginx are enabled on system boot:
```bash
sudo systemctl enable docker
sudo systemctl enable nginx
```
To test resilience, reboot the VM:
```bash
sudo reboot
```
Wait 60 seconds, then reconnect via SSH and verify:
```bash
docker compose ps
```
All containers should automatically be back in `Up` status.

---

### Section N: Troubleshooting

| Issue | Root Cause | Solution |
| :--- | :--- | :--- |
| **Site cannot be reached on port 80/443** | Oracle Ubuntu iptables blocking ports | Run `sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT` and `sudo netfilter-persistent save`. |
| **MySQL connection refused** | MySQL container still initializing on first launch | Wait 15 seconds; Docker Compose healthcheck will start `web` once MySQL is healthy. Check with `docker compose logs db`. |
| **504 Gateway Timeout during Model Studio training** | Nginx default timeout (60s) reached during 5,000-sample training | Ensure `proxy_read_timeout 180s;` is set inside the Nginx `/` block. |
| **OpenRouter AI Analyzer Error** | `OPENROUTER_API_KEY` missing or invalid | Verify `.env` contains valid key. Core BullyMail detection remains 100% operational locally in Normal mode. |

---

### Section O: How to Stop or Remove the Deployment

To temporarily stop the application:
```bash
cd /home/ubuntu/bullymail
docker compose stop
```

To restart the application:
```bash
docker compose start
```

To completely remove containers while preserving database and model data:
```bash
docker compose down
```

To completely wipe all containers, images, and data volumes:
```bash
docker compose down -v --rmi all
```

---

## 📋 FINAL DEPLOYMENT CHECKLIST

- [ ] Oracle Cloud Compute instance is `VM.Standard.A1.Flex` (ARM64).
- [ ] OCPUs = 2, RAM = 12 GB, Boot Volume = 50 GB (all within Always Free).
- [ ] Oracle VCN Security List only opens ports 22, 80, 443 (ports 3306 and 5000 blocked).
- [ ] OS-level iptables rules opened for ports 80 and 443 and saved with `netfilter-persistent`.
- [ ] Docker and Docker Compose installed and running.
- [ ] `.env` created on server with strong generated keys (`chmod 600 .env`).
- [ ] `.env` is NOT tracked or committed to Git.
- [ ] MySQL is internal only (no host port 3306 mapping).
- [ ] Web application bound to `127.0.0.1:5000` (reverse-proxied via Nginx).
- [ ] Free Let's Encrypt SSL certificate configured and auto-renewing.
- [ ] Verified login, threat analyzer, and dashboard over HTTPS.
- [ ] Total deployment cost is verified at **₹0.00**.
