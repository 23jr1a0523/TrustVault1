# TrustVault — Threat Model, Security Analysis & Access Control Architecture

## 1. Overview & Security Philosophy
TrustVault is designed as a zero-trust, confidential document storage and sharing platform built for the Snovasys Fresher Hiring Challenge 2026. Because documents uploaded by users may contain sensitive identity, financial, legal, or intellectual property files, security is enforced strictly at the server level, never trusting client-side claims or hidden UI elements.

---

## 2. Threat Modeling & Risk Mitigation Matrix

| Threat ID | Threat Category | Risk Description | Attack Vector | Mitigation & Technical Implementation | Automated Test Case |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **THREAT-01** | Insecure Direct Object Reference (IDOR) | Attacker alters document ID in URL to view, download, or delete other users' confidential files | `GET /documents/download/123`<br>`POST /documents/delete/123` | Server checks `owner_id == session['user_id']` or verifies an active record in `document_permissions` before authorizing download. Delete is restricted to owner or admin. | `test_url_manipulation_document_id_bypass_prevented`, `test_owners_cannot_manage_another_owners_document` |
| **THREAT-02** | Ephemeral Cloud Storage Loss | Storing uploads on Render's ephemeral container filesystem causes complete data wipe on restart or redeploy | File system wipe | Integrated **Supabase Storage** with private bucket `trustvault-documents`. Server uploads files via Supabase Python SDK using UUID paths (`documents/{user_id}/{uuid}.{ext}`). | `test_invalid_file_upload_rejected`, storage upload unit tests |
| **THREAT-03** | Document Tampering & Bit Rot | Files modified in storage or corrupted during transit without detection | Storage tampering or transmission corruption | Cryptographic **SHA-256** hash calculated on raw bytes at upload time and stored in database. On download, hash is recalculated; any mismatch triggers HTTP 409 Conflict and an audit alert. | `test_sha256_verification_detects_document_tampering` |
| **THREAT-04** | Privilege Escalation | Malicious user injects `role=admin` during account creation to gain administrator access | `POST /register` with `role=admin` form payload | Backend unconditionally assigns `role='user'` during registration. Role elevation requires offline administrator script (`make_admin.py`) or direct database administration. | `test_ordinary_registration_cannot_create_administrators` |
| **THREAT-05** | Cross-Site Request Forgery (CSRF) | Malicious third-party website submits unauthorized document deletion or upload requests using victim's active session | Phishing link or malicious iframe submitting POST forms | Cryptographic per-session CSRF token generated and verified on all state-changing endpoints (`POST`, `PUT`, `DELETE`). | `test_csrf_protection_enforced` |
| **THREAT-06** | Session Hijacking & Token Theft | Session cookies intercepted via network eavesdropping or malicious client scripts (XSS) | Cookie extraction via JavaScript or unencrypted HTTP | Enforced `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SAMESITE='Lax'`, and HTTPS `SESSION_COOKIE_SECURE=True` in production. | Session configuration validation |
| **THREAT-07** | Public Storage Exposure | Confidential documents made publicly accessible via guessable URLs or open cloud buckets | Search engine crawling or link enumeration | Supabase bucket created strictly as `public: False`. Files are downloaded server-side or accessed via temporary 60-second signed bearer URLs that expire immediately. | `test_unauthorized_users_cannot_obtain_signed_urls` |
| **THREAT-08** | Unauthorized Elevation to Admin Pages | Viewer or Owner attempts to view audit trail or user accounts | Direct access to `/admin/audit-logs` or `/admin/users` | `@admin_required` decorator validates `session.get('role') == 'admin'`. Unauthorized attempts are blocked with HTTP 403 and logged with IP address. | `test_viewers_cannot_access_admin_only_routes`, `test_audit_logs_restricted_to_administrators` |
| **THREAT-09** | Revoked Access Re-use | User whose access was revoked continues to download cached or active links | `GET /documents/download/<id>` after owner revoked permission | Database permission check executes dynamically on every request. Immediate denial (403) upon revocation. | `test_revoked_access_denied_on_subsequent_requests` |
| **THREAT-10** | Unrestricted File Upload & Remote Code Execution (RCE) | Malicious file types (.exe, .sh, .py, .php) uploaded to compromise server | `POST /documents/upload` with executable file | Extension whitelist (`pdf, txt, docx, png, jpg, jpeg`), secure filename sanitization (`secure_filename`), and 5MB hard payload limit. | `test_invalid_file_upload_rejected` |

---

## 3. Role-Based Access Control (RBAC) Specification

### Role 1: Administrator
- **Dashboard:** Can view system-wide stats (total users, total documents, total shared documents).
- **Audit Logs:** Full access to view comprehensive audit records, including success/failure status and IP addresses.
- **User Directory:** View list of registered usernames, roles, and registration dates.
- **Access Restrictions:** Does not automatically bypass owner privacy unless explicitly authorized or managing system security.

### Role 2: Document Owner
- **Upload:** Upload documents up to 5MB with category assignment.
- **Download:** Download owned documents with SHA-256 verification or obtain 60s signed URLs.
- **Share:** Grant `READ` or `EDIT` permissions to any registered user.
- **Revoke:** Revoke previously granted permissions at any time.
- **Delete:** Permanently delete owned documents from Supabase Storage and database.

### Role 3: Viewer
- **View & Download:** Can view and download documents explicitly shared with them.
- **Restrictions:** 
  - Cannot delete documents they do not own.
  - Cannot grant or revoke access to other users.
  - Cannot access administrative routes (`/admin/users`, `/admin/audit-logs`).
  - Cannot access documents belonging to other owners unless an explicit permission record exists.

---

## 4. Remaining Limitations & Future Hardening
1. **Rate Limiting:** Implement Flask-Limiter for brute-force protection on `/login` and `/register`.
2. **Virus/Malware Scanning:** Integrate ClamAV or serverless scan trigger on Supabase storage upload.
3. **End-to-End Encryption (E2EE):** Add client-side AES-GCM encryption before documents leave the browser for zero-knowledge storage.
