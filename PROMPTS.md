# TrustVault — AI Interaction & Engineering Log (PROMPTS.md)

This log records five genuine technical interactions with AI engineering tools during the design, hardening, and deployment of TrustVault for the Snovasys Fresher Hiring Challenge 2026.

---

### Interaction 1: Storage Architecture & Ephemeral Filesystem Risk
- **Date:** 2026-10-24
- **Prompt:**
  > "Inspect the existing file upload and download implementation in `run.py`. How does it handle document storage, and what will happen when deployed to Render?"
- **AI Proposal / Finding:**
  The AI noted that `run.py` wrote uploaded file bytes to `private_uploads/<uuid>.<ext>` on the local container filesystem.
- **What Was Wrong / Vulnerability:**
  Render Web Services run in ephemeral containers. Any redeploy, zero-downtime rollover, or container sleep permanently deletes all locally stored user documents, causing irreversible data loss.
- **The Correction:**
  Engineered a dedicated module `supabase_storage.py` that connects server-side to Supabase Storage via the Supabase Python SDK. Files are uploaded to a private bucket (`trustvault-documents`) using unique generated paths (`documents/{owner_id}/{uuid}.{ext}`). A local disk fallback was retained for offline testing without cloud credentials.
- **Evidence:**
  `supabase_storage.py` created and integrated with `upload_document_to_supabase()` and `create_signed_download_url()`. Verified locally and automated in test suite.

---

### Interaction 2: Authorization, RBAC & Document Sharing (Access Control)
- **Date:** 2026-10-24
- **Prompt:**
  > "Review the authorization logic in `run.py` and `database.py`. The project requires three roles: Administrator, Document Owner, and Viewer. How are these currently implemented?"
- **AI Proposal / Finding:**
  The AI discovered that the application only had a binary `user` vs `admin` role and strictly enforced `WHERE id = ? AND owner_id = ?`. There was no mechanism to share documents or grant Viewer access.
- **What Was Wrong / Vulnerability:**
  There was no Viewer role, no permissions table, and no sharing route. Users could neither share files nor access files shared with them.
- **The Correction:**
  Created the `document_permissions` schema (`document_id`, `user_id`, `permission`, `granted_by`) with cascade deletion. Updated `/documents/download/<id>` to allow access if `is_owner`, `is_admin`, or if a valid `document_permissions` record exists. Created `/documents/share/<id>` and `/documents/revoke/<id>` endpoints protected by strict owner authorization checks.
- **Evidence:**
  Automated tests in `tests/test_security.py`:
  - `test_viewers_cannot_grant_or_revoke_access` (PASSED)
  - `test_owners_cannot_manage_another_owners_document` (PASSED)
  - `test_url_manipulation_document_id_bypass_prevented` (PASSED)
  - `test_revoked_access_denied_on_subsequent_requests` (PASSED)

---

### Interaction 3: Audit Logging Blind Spots for Denied Actions
- **Date:** 2026-10-24
- **Prompt:**
  > "Review the audit logging implementation. Does it record failed actions, unauthorized URL manipulation, or denied access attempts?"
- **AI Proposal / Finding:**
  The initial `audit_logs` table only recorded `user_id`, `action`, `document_name`, and timestamp. Logging only fired on successful `UPLOAD` and successful `DOWNLOAD`.
- **What Was Wrong / Vulnerability:**
  Security incidents (unauthorized download attempts, URL ID manipulation, failed logins, CSRF failures, and SHA-256 hash mismatches) were completely invisible to the administrator.
- **The Correction:**
  Migrated `audit_logs` schema to include `status` (`SUCCESS` vs `DENIED`), `ip_address` (extracted safely via `X-Forwarded-For`), and `details`. Added audit triggers for `UNAUTHORIZED_DOWNLOAD_ATTEMPT`, `LOGIN_FAILED`, `CSRF_VIOLATION`, and `INTEGRITY_CHECK_FAILED`.
- **Evidence:**
  Automated test `test_denied_access_recorded_in_audit_logs` in `tests/test_security.py` verifies that an unauthorized download attempt writes an audit record with `status='DENIED'`.

---

### Interaction 4: CSRF Vulnerability & Session Cookie Hardening
- **Date:** 2026-10-24
- **Prompt:**
  > "Audit the session management and form handling for CSRF and cookie vulnerabilities in `run.py`."
- **AI Proposal / Finding:**
  The AI found that `SECRET_KEY` fell back to a hardcoded string (`"dev-only-change-this-key"`), session cookies lacked `HttpOnly` and `SameSite` flags, and POST forms lacked CSRF tokens.
- **What Was Wrong / Vulnerability:**
  An attacker could forge session cookies if `SECRET_KEY` was omitted, or execute Cross-Site Request Forgery (CSRF) to delete files or share confidential documents from an authenticated victim's browser.
- **The Correction:**
  1. Configured `app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))` ensuring a cryptographically strong key is always generated.
  2. Enforced `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SAMESITE='Lax'`, and production HTTPS cookies.
  3. Built custom CSRF middleware with per-session tokens injected into all HTML forms (`csrf_token()`) and validated before processing POST requests.
- **Evidence:**
  Automated test `test_csrf_protection_enforced` confirms that POST requests lacking a valid CSRF token are rejected with HTTP 403 Forbidden.

---

### Interaction 5: Database Compatibility & Dual PostgreSQL/SQLite Engine
- **Date:** 2026-10-24
- **Prompt:**
  > "How can we migrate the database from SQLite to Supabase PostgreSQL without breaking local developer workflows or requiring two separate codebases?"
- **AI Proposal / Finding:**
  Directly switching to `psycopg2` would cause syntax errors because SQLite queries use `?` parameter placeholders while PostgreSQL requires `%s`, and SQLite returns `sqlite3.Row` while standard `psycopg2` returns tuples.
- **What Was Wrong:**
  Hardcoding PostgreSQL-only syntax would break offline testing and require a live cloud connection for simple unit tests.
- **The Correction:**
  Engineered a `PostgresConnectionWrapper` class in `database.py` that utilizes `RealDictCursor` for dictionary access (`row['column']`) and transparently adapts `?` parameter placeholders to `%s`. If `DATABASE_URL` is configured, it connects to Supabase PostgreSQL; otherwise, it falls back to local SQLite.
- **Evidence:**
  `python database.py` executes successfully on both engines. Unit tests run completely isolated against in-memory/temporary SQLite while production connects to Supabase PostgreSQL via connection pooling.
