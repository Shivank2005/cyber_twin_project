# 🛡️ CyberX AI Digital Twin — SecureX

> **An AI-powered cybersecurity platform that functions as an autonomous digital twin for real-time threat detection, classification, and neutralization.**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.x-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![MySQL](https://img.shields.io/badge/MySQL-8.0-4479A1?style=for-the-badge&logo=mysql&logoColor=white)](https://mysql.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Architecture](#architecture)
- [Installation](#installation)
- [Environment Variables](#environment-variables)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Project Structure](#project-structure)
- [Contributing](#contributing)

---

## 🔍 Overview

SecureX is a full-stack cybersecurity digital twin that combines **three AI/ML models**, an **active Web Application Firewall (WAF)**, **persistent threat analytics**, and a **premium B2B SaaS dashboard** into a single unified platform.

It doesn't just simulate — it **actively defends** against real SQL injection and XSS attacks on its own endpoints, logs every incident to a MySQL database, and provides enterprise-grade analytics and reporting.

---

## ✨ Features

### 🔐 Authentication & Security
| Feature | Description |
|---------|-------------|
| **Bcrypt Password Hashing** | All passwords stored with bcrypt salted hashes — zero plain-text storage |
| **Flask-Login Sessions** | Session-based authentication with `@login_required` route protection |
| **Dual Directory Storage** | User credentials synced to both MySQL and LDAP (OpenLDAP via Docker) |
| **Session Timeout** | Auto-logout after 15 minutes of inactivity |
| **Brute Force Protection** | 5 failed login attempts in 60 seconds triggers auto-lockout + CRITICAL log |
| **Password Strength Meter** | Real-time JS validation (length, uppercase, lowercase, numbers, special chars) |
| **Role-Based Access** | Admin panel restricted to configured admin users only |

### 🛡️ Active Web Application Firewall (WAF)
The `@app.before_request` middleware intercepts **every HTTP request** and scans all URL parameters and form data against the AI detection engine.

**If a threat is detected:**
- Connection is instantly killed → `403 FORBIDDEN` page
- Incident logged to `threat_logs` with severity `CRITICAL`
- Email alert sent to configured administrators

**Attack signatures detected:** `OR 1=1`, `DROP TABLE`, `UNION SELECT`, `--`, `xp_cmdshell`, `information_schema`, `<script>`, `javascript:`, `onerror=`, `onload=`, `document.cookie`, `alert(`

### 🤖 AI Threat Detection Models

| Agent | Target | Method | Dataset |
|-------|--------|--------|---------|
| **Agent 1** | SQL Injection | Pattern-matching engine | `advanced_generated_sql_injections.csv` |
| **Agent 2** | XSS Attacks | Pre-trained Random Forest (`.pkl`) | `Data_66_featurs.csv` (20MB, 66 features) |
| **Agent 3** | Session Hijacking | Random Forest + CountVectorizer | `LDAP.csv` (network flow data) |

All models use **lazy caching** — loaded once into memory, subsequent requests resolve instantly.

### 📊 Dashboard & Analytics
- **Real-time status cards** — Network Status, Intercepted Threats, Defense Readiness
- **Line chart** — "Detections Over Time" with ticking animation engine
- **Doughnut chart** — Threat distribution by category (SQL/XSS/Session)
- **Live Telemetry Console** — Scrolling monospace feed simulating real-time traffic monitoring
- **Custom Payload Scanner** — Type any string to instantly test it against the AI engine

### 📋 Enterprise Features
| Feature | Route | Description |
|---------|-------|-------------|
| **Threat Audit Log** | `/threats` | Full incident table with severity badges, bar + doughnut charts |
| **CSV Report Export** | `/export` | One-click download of `securex_threat_report.csv` |
| **Admin Panel** | `/admin` | User management, system stats, recent threats, API docs |
| **REST API** | `/api/v1/scan` | JSON API for external payload scanning (SaaS model) |
| **Email Alerts** | Automatic | SMTP notifications on CRITICAL threat detection |

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.10+, Flask, Flask-Login |
| **Database** | MySQL 8.0 |
| **Directory** | OpenLDAP (Docker) |
| **ML/AI** | Scikit-learn, Pandas, NumPy, Joblib |
| **Security** | bcrypt, WAF middleware, rate limiting |
| **Frontend** | HTML5, CSS3 (Glassmorphism), Chart.js |
| **Config** | python-dotenv |

---

## 🏗️ Architecture

```
Browser ──► WAF Middleware ──► Route Handler ──► AI Agents ──► MySQL
                │                                                │
                ├── THREAT → 403 Block Page + DB Log + Email     │
                │                                                │
                └── CLEAN → Dashboard UI ◄── Chart.js ◄──────────┘
```

---

## 🚀 Installation

### Prerequisites
- Python 3.10+
- MySQL Server 8.0+
- Docker (for OpenLDAP)

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/Shivank2005/cyber_twin_project.git
cd cyber_twin_project

# 2. Create virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

# 3. Install dependencies
pip install flask flask-login mysql-connector-python ldap3 bcrypt python-dotenv scikit-learn pandas numpy joblib

# 4. Configure environment
copy .env.example .env
# Edit .env with your MySQL/LDAP credentials

# 5. Start MySQL and create database
mysql -u root -p -e "CREATE DATABASE IF NOT EXISTS cyberx;"

# 6. Start LDAP (Docker)
docker run -d --name openldap \
  -p 389:389 \
  -e LDAP_ORGANISATION="CyberX" \
  -e LDAP_DOMAIN="cyberx.local" \
  -e LDAP_ADMIN_PASSWORD="admin" \
  osixia/openldap:latest

# 7. Run the application
python app.py
```

The app will be available at **http://127.0.0.1:5001**

---

## 🔧 Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DB_HOST` | Yes | MySQL server hostname |
| `DB_USER` | Yes | MySQL username |
| `DB_PASSWORD` | Yes | MySQL password |
| `DB_NAME` | Yes | Database name |
| `LDAP_SERVER` | Yes | LDAP server URL |
| `LDAP_USER_DN` | Yes | LDAP admin DN |
| `LDAP_PASSWORD` | Yes | LDAP admin password |
| `LDAP_BASE_DN` | Yes | LDAP base DN |
| `FLASK_SECRET_KEY` | Yes | Flask session encryption key |
| `ADMIN_USERS` | No | Comma-separated admin usernames |
| `SMTP_SERVER` | No | SMTP server for email alerts |
| `SMTP_PORT` | No | SMTP port (default: 587) |
| `SMTP_USER` | No | SMTP username |
| `SMTP_PASS` | No | SMTP password / app password |
| `ALERT_EMAIL` | No | Email to receive threat alerts |

---

## 📖 Usage

### Dashboard
1. Register at `/register` → Login at `/login`
2. Dashboard shows real-time charts, telemetry, and threat metrics
3. Use the **Payload Scanner** to test any string against the AI engine
4. Run **SQL/XSS/Session** evaluations from the Security Modules

### Testing the WAF
```bash
# This will be blocked by the WAF:
curl -X POST http://127.0.0.1:5001/login -d "username=OR 1=1&password=test"
# Returns: 403 FORBIDDEN + REQUEST BLOCKED page
```

### Admin Panel
Access `/admin` (requires admin role) to view all users, recent threats, and system stats.

---

## 📡 API Reference

### Scan Payload
```http
POST /api/v1/scan
Content-Type: application/json
```

**Request:**
```json
{
  "payload": "SELECT * FROM users WHERE '1'='1'"
}
```

**Response (Threat Detected):**
```json
{
  "payload": "SELECT * FROM users WHERE '1'='1'",
  "status": "THREAT_DETECTED",
  "threats": [
    {"type": "SQL Injection", "severity": "CRITICAL"}
  ]
}
```

**Response (Clean):**
```json
{
  "payload": "hello world",
  "status": "CLEAN"
}
```

---

## 📁 Project Structure

```
CyberX-AI-Digital-Twin/
├── app.py                          # Main Flask application (all routes + WAF)
├── .env                            # Environment variables (not committed)
├── .env.example                    # Environment template
├── requirements.txt                # Python dependencies
│
├── models/
│   ├── AI_agent1/                  # SQL Injection Detection
│   │   ├── sql_injection_detectio.py
│   │   └── advanced_generated_sql_injections.csv
│   ├── AI_agent2/                  # XSS Attack Prediction
│   │   ├── XSS_attack_prediction.py
│   │   ├── xss_model.pkl
│   │   └── Data_66_featurs.csv
│   └── AI_agent3/                  # Session Hijacking Detection
│       ├── session_hijacking.py
│       ├── session_model.pkl
│       └── LDAP.csv
│
├── templates/
│   ├── index.html                  # Landing page
│   ├── login.html                  # Login with brute force protection
│   ├── register.html               # Registration with password strength meter
│   ├── home.html                   # Main dashboard (charts + telemetry + scanner)
│   ├── threats.html                # Threat audit log with analytics
│   ├── admin.html                  # Admin panel
│   └── waf_blocked.html            # 403 WAF block page
│
└── static/
    └── style.css                   # Global stylesheet (glassmorphism theme)
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-feature`)
3. Commit your changes (`git commit -m 'Add new feature'`)
4. Push to the branch (`git push origin feature/new-feature`)
5. Open a Pull Request

---

## 👤 Author

**Shivank** — [@Shivank2005](https://github.com/Shivank2005)

---

<p align="center">
  <b>SecureX</b> — Next-Gen AI-Driven Cybersecurity Digital Twin
</p>
