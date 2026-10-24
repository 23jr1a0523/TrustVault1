# 🔐 TrustVault — Secure, AI-Powered Document Management & Vault

TrustVault is a confidential document sharing and verification platform developed for the **Snovasys Fresher Hiring Challenge 2026**. Built with Python Flask and integrated with Supabase, TrustVault combines server-side role-based access control (RBAC), private object storage, SHA-256 file integrity verification, and audit logging into a fast, emerald-green dark-themed web application.

---

## 🌟 Key Features

### 1. Role-Based Access Control (RBAC)
- **Administrator:** System oversight dashboard, total platform statistics, registered user directory, and activity audit logs with IP tracking.
- **Document Owner:** Upload files up to 5MB, assign categories, manage permissions, share documents with selected users as `READ` or `EDIT`, revoke access at any time, and delete owned files.
- **Viewer:** Access and download documents explicitly shared with them. Viewers cannot delete files, grant permissions, or view admin audit logs.

### 2. Private Supabase Storage & Ephemeral Loss Prevention
- Uploaded files are stored in a private Supabase Storage bucket (`trustvault-documents`), eliminating data loss from Render's ephemeral container filesystem.
- Documents are saved using secure, server-generated UUID object paths (`documents/{owner_id}/{uuid}.{ext}`).
- Authorized downloads are served directly with `Cache-Control: no-store` headers or via temporary 60-second signed bearer URLs.

### 3. Cryptographic SHA-256 Integrity Verification
- A SHA-256 cryptographic hash is calculated on raw bytes during upload and stored in the database.
- Upon every download request, the file content is recalculated against the stored reference. If any byte was altered or tampered with, download is blocked with HTTP 409 Conflict and an audit alert is triggered.

### 4. Dual-Engine Persistent Database (PostgreSQL / SQLite)
- **Production (Supabase PostgreSQL):** Connects via `DATABASE_URL` (connection pooling with SSL) using `psycopg2`.
- **Local / Testing (SQLite):** Automatically falls back to local `trustvault.db` when offline or running automated tests.

### 5. Enterprise-Grade Security
- **Per-Session CSRF Protection:** Cryptographic tokens on all state-changing `POST` requests.
- **Hardened Cookies:** `HttpOnly`, `SameSite=Lax`, and production `Secure` flags.
- **Privilege Escalation Protection:** User self-registration strictly enforces the `user` role; admin elevation requires offline CLI scripts or database administration.
- **Audit Logging:** Logs successful events (`UPLOAD`, `DOWNLOAD`, `SHARE`, `REVOKE`, `DELETE`, `LOGIN`) and security violations (`UNAUTHORIZED_DOWNLOAD_ATTEMPT`, `UNAUTHORIZED_ADMIN_ACCESS`, `CSRF_VIOLATION`, `LOGIN_FAILED`).

---

## 🛠️ Technology Stack
- **Backend:** Python 3.13, Flask 3.x
- **WSGI Production Server:** Gunicorn 26.x
- **Cloud Database:** Supabase PostgreSQL
- **Cloud Storage:** Supabase Storage (Private Bucket)
- **Security & Cryptography:** Werkzeug (`generate_password_hash`), Python `hashlib` (SHA-256), Python `secrets`
- **AI Assistant:** Google Gemini API (`gemini-3.5-flash-lite` via `google-genai`)
- **Deployment Platform:** Render Web Service (Free Tier)

---

## 🚀 Local Installation & Setup

### Prerequisites
- Python 3.10+ (Tested on Python 3.13)
- Git

### 1. Clone the Repository
```powershell
git clone https://github.com/23jr1a0523/TrustVault1.git
cd TrustVault1
```

### 2. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 3. Configure Environment Variables
Copy `.env.example` to `.env`:
```powershell
Copy-Item .env.example .env
```
Open `.env` and fill in your configuration:
```env
# Flask Secret Key
SECRET_KEY=your-custom-secret-key-at-least-32-chars

# Supabase Storage & API
SUPABASE_URL=https://your-project-id.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your-supabase-service-role-key
SUPABASE_BUCKET=trustvault-documents

# Supabase PostgreSQL Connection String
DATABASE_URL=postgresql://postgres.your-project:your-password@aws-0-region.pooler.supabase.com:6543/postgres?sslmode=require

# Google Gemini API Key (Optional, for AI Security Assistant)
GEMINI_API_KEY=your-gemini-api-key
FLASK_ENV=development
```
*(Note: If you leave `DATABASE_URL` or `SUPABASE_URL` unset, TrustVault automatically uses local SQLite and local storage for offline development!)*

### 4. Initialize Database
```powershell
python database.py
```

### 5. Run the Application
```powershell
python run.py
```
Open your browser at [http://127.0.0.1:5000](http://127.0.0.1:5000).

---

## 🧪 Running Automated Security Tests
TrustVault includes a comprehensive automated test suite covering 15 security, authorization, and integrity scenarios.
Run tests using Python's built-in `unittest`:
```powershell
python -m unittest tests/test_security.py -v
```
All tests execute against an isolated temporary database without modifying your production data.

---

## 🌐 Deploying to Render

TrustVault is pre-configured for 1-click deployment on **Render** using the included `render.yaml` blueprint.

### Manual Configuration on Render:
1. Log in to [Render Dashboard](https://dashboard.render.com/).
2. Click **New +** -> **Web Service**.
3. Connect your GitHub repository (`https://github.com/23jr1a0523/TrustVault1`).
4. Configure service settings:
   - **Name:** `trustvault`
   - **Environment:** `Python`
   - **Region:** `Oregon (US West)` or your preferred region
   - **Branch:** `main`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn run:app`
   - **Plan:** `Free`
5. In **Environment Variables**, add:
   - `SECRET_KEY`: Random 32+ character string
   - `SUPABASE_URL`: Your Supabase Project URL
   - `SUPABASE_SERVICE_ROLE_KEY`: Your Supabase Service Role Key
   - `SUPABASE_BUCKET`: `trustvault-documents`
   - `DATABASE_URL`: Your Supabase PostgreSQL Connection URI
   - `GEMINI_API_KEY`: Your Google Gemini API key
   - `FLASK_ENV`: `production`
6. Click **Create Web Service**.
7. Render will build and deploy the app with automatic health monitoring via `/health`.

---

## 🛡️ Promoting an Administrator
To promote a registered user to administrator, run the local administration script:
```powershell
python make_admin.py
```
Enter the registered username, and the user's role will be updated to `admin`.

---

## 📜 Documentation & Security Links
- **[THREATS.md](file:///c:/Users/aksha/OneDrive/Attachments/Desktop/TrustVault1/THREATS.md):** Complete threat modeling, RBAC specifications, attack vectors, and mitigations.
- **[PROMPTS.md](file:///c:/Users/aksha/OneDrive/Attachments/Desktop/TrustVault1/PROMPTS.md):** Genuine dated AI interaction log detailing access control, storage, and audit logging decisions.

---

## 📄 License & AI Disclosure
Developed for the **Snovasys Fresher Hiring Challenge 2026**.
- **AI Tools Disclosure:** Development and code hardening were assisted by Google Gemini API and Pair Programming agents for architecture review, security testing, and bug detection.
