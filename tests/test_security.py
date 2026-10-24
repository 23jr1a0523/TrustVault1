import os
import tempfile
import unittest
import hashlib
from io import BytesIO
from pathlib import Path

# Ensure test uses a separate isolated SQLite database
temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
temp_db.close()
os.environ["DATABASE_URL"] = ""  # Force local test DB
os.environ["SECRET_KEY"] = "test-secret-key-32-characters-minimum"

# Set up database path override for testing
import database
database.DB_PATH = Path(temp_db.name)

from run import app, get_db_connection, init_db, generate_password_hash


class TrustVaultSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = True
        init_db()

    @classmethod
    def tearDownClass(cls):
        try:
            os.unlink(temp_db.name)
        except Exception:
            pass

    def setUp(self):
        self.client = app.test_client()
        # Clean and reinitialize test tables before each test
        conn = get_db_connection()
        conn.execute("DELETE FROM document_permissions")
        conn.execute("DELETE FROM audit_logs")
        conn.execute("DELETE FROM documents")
        conn.execute("DELETE FROM users")
        conn.commit()

        # Seed test users: admin, owner_a, owner_b, viewer_c
        self.admin_id = conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
            ("admin_user", generate_password_hash("AdminPass123!"))
        ).lastrowid

        self.owner_a_id = conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'user')",
            ("owner_a", generate_password_hash("OwnerPass123!"))
        ).lastrowid

        self.owner_b_id = conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'user')",
            ("owner_b", generate_password_hash("OwnerPass123!"))
        ).lastrowid

        self.viewer_c_id = conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'user')",
            ("viewer_c", generate_password_hash("ViewerPass123!"))
        ).lastrowid

        # Seed test document for Owner A
        content = b"Top Secret Project Specs by Owner A"
        self.doc_a_hash = hashlib.sha256(content).hexdigest()
        self.doc_a_id = conn.execute(
            """
            INSERT INTO documents (owner_id, original_name, stored_name, storage_path, sha256_hash, file_size, category)
            VALUES (?, 'specs_a.pdf', 'stored_a.pdf', 'documents/test/stored_a.pdf', ?, ?, 'Confidential')
            """,
            (self.owner_a_id, self.doc_a_hash, len(content))
        ).lastrowid

        # Seed test document for Owner B
        content_b = b"Owner B Private Financials"
        self.doc_b_hash = hashlib.sha256(content_b).hexdigest()
        self.doc_b_id = conn.execute(
            """
            INSERT INTO documents (owner_id, original_name, stored_name, storage_path, sha256_hash, file_size, category)
            VALUES (?, 'finance_b.pdf', 'stored_b.pdf', 'documents/test/stored_b.pdf', ?, ?, 'Financial')
            """,
            (self.owner_b_id, self.doc_b_hash, len(content_b))
        ).lastrowid

        conn.commit()
        conn.close()

    def _login(self, username, user_id, role="user"):
        with self.client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["username"] = username
            sess["role"] = role
            sess["_csrf_token"] = "test-valid-csrf-token"

    # 1. Unauthenticated users cannot access protected pages
    def test_unauthenticated_cannot_access_protected_pages(self):
        for endpoint in ["/dashboard", "/documents", "/admin/audit-logs", "/admin/users", "/profile"]:
            res = self.client.get(endpoint, follow_redirects=False)
            self.assertEqual(res.status_code, 302, f"Unauthenticated access to {endpoint} must redirect to /login")
            self.assertIn("/login", res.headers.get("Location", ""))

    # 2. Viewers/regular users cannot access admin-only routes
    def test_viewers_cannot_access_admin_only_routes(self):
        self._login("viewer_c", self.viewer_c_id, role="user")
        for admin_endpoint in ["/admin/audit-logs", "/admin/users"]:
            res = self.client.get(admin_endpoint)
            self.assertEqual(res.status_code, 403, f"Regular user should receive 403 on {admin_endpoint}")

    # 3. Viewers cannot grant or revoke access
    def test_viewers_cannot_grant_or_revoke_access(self):
        self._login("viewer_c", self.viewer_c_id, role="user")
        # Viewer tries to share Owner A's document
        res = self.client.post(
            f"/documents/share/{self.doc_a_id}",
            data={"target_username": "owner_b", "permission": "READ", "csrf_token": "test-valid-csrf-token"}
        )
        self.assertEqual(res.status_code, 403, "Non-owner viewer cannot grant document permissions")

    # 4. Owners cannot manage or delete another owner's private document
    def test_owners_cannot_manage_another_owners_document(self):
        self._login("owner_a", self.owner_a_id, role="user")
        # Owner A tries to delete Owner B's document
        res = self.client.post(
            f"/documents/delete/{self.doc_b_id}",
            data={"csrf_token": "test-valid-csrf-token"}
        )
        self.assertEqual(res.status_code, 403, "Owner A cannot delete Owner B's document")

    # 5. Users cannot bypass permissions by changing document IDs in URLs
    def test_url_manipulation_document_id_bypass_prevented(self):
        self._login("viewer_c", self.viewer_c_id, role="user")
        # Viewer C tries to download Owner A's document without permission
        res = self.client.get(f"/documents/download/{self.doc_a_id}")
        self.assertEqual(res.status_code, 403, "Tampering with document_id in URL must be rejected with 403")

    # 6. READ-only users cannot delete documents
    def test_readonly_users_cannot_delete_documents(self):
        # Grant READ access to Viewer C
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO document_permissions (document_id, user_id, permission, granted_by) VALUES (?, ?, 'READ', ?)",
            (self.doc_a_id, self.viewer_c_id, self.owner_a_id)
        )
        conn.commit()
        conn.close()

        self._login("viewer_c", self.viewer_c_id, role="user")
        res = self.client.post(
            f"/documents/delete/{self.doc_a_id}",
            data={"csrf_token": "test-valid-csrf-token"}
        )
        self.assertEqual(res.status_code, 403, "READ-only user must be forbidden from deleting the document")

    # 7. Revoked access is denied on subsequent requests
    def test_revoked_access_denied_on_subsequent_requests(self):
        conn = get_db_connection()
        perm_id = conn.execute(
            "INSERT INTO document_permissions (document_id, user_id, permission, granted_by) VALUES (?, ?, 'READ', ?)",
            (self.doc_a_id, self.viewer_c_id, self.owner_a_id)
        ).lastrowid
        conn.commit()
        conn.close()

        # Owner A revokes access
        self._login("owner_a", self.owner_a_id, role="user")
        revoke_res = self.client.post(
            f"/documents/revoke/{perm_id}",
            data={"csrf_token": "test-valid-csrf-token"}
        )
        self.assertEqual(revoke_res.status_code, 302)

        # Viewer C subsequent request must be denied
        self._login("viewer_c", self.viewer_c_id, role="user")
        subsequent_res = self.client.get(f"/documents/download/{self.doc_a_id}")
        self.assertEqual(subsequent_res.status_code, 403, "Revoked user must be denied subsequent download access")

    # 8. Unauthorized users cannot obtain signed download URLs
    def test_unauthorized_users_cannot_obtain_signed_urls(self):
        self._login("viewer_c", self.viewer_c_id, role="user")
        res = self.client.get(f"/documents/signed-url/{self.doc_a_id}")
        self.assertEqual(res.status_code, 403, "Unauthorized user cannot obtain signed download URL")

    # 9. Ordinary registration cannot create administrators
    def test_ordinary_registration_cannot_create_administrators(self):
        # Attacker posts role='admin' to /register
        with self.client.session_transaction() as sess:
            sess["_csrf_token"] = "test-valid-csrf-token"

        res = self.client.post(
            "/register",
            data={
                "username": "sneaky_admin_attempt",
                "password": "Password123!",
                "role": "admin",
                "csrf_token": "test-valid-csrf-token"
            }
        )
        self.assertEqual(res.status_code, 302)

        conn = get_db_connection()
        user = conn.execute("SELECT role FROM users WHERE username = 'sneaky_admin_attempt'").fetchone()
        conn.close()

        self.assertIsNotNone(user)
        self.assertEqual(user["role"], "user", "Registration must force user role and ignore attacker input")

    # 10. Invalid or oversized file uploads are rejected
    def test_invalid_file_upload_rejected(self):
        self._login("owner_a", self.owner_a_id, role="user")
        # Try uploading a disallowed file (.exe)
        data = {
            "document": (BytesIO(b"MALICIOUS_EXE_CONTENT"), "exploit.exe"),
            "category": "General",
            "csrf_token": "test-valid-csrf-token",
        }
        res = self.client.post("/documents/upload", data=data, content_type="multipart/form-data")
        self.assertEqual(res.status_code, 400, "Unsupported file extension must return 400 Bad Request")

    # 11. Audit logs are restricted to administrators
    def test_audit_logs_restricted_to_administrators(self):
        # Admin access allowed
        self._login("admin_user", self.admin_id, role="admin")
        admin_res = self.client.get("/admin/audit-logs")
        self.assertEqual(admin_res.status_code, 200, "Administrator must be granted access to audit logs")

        # Owner A access denied
        self._login("owner_a", self.owner_a_id, role="user")
        user_res = self.client.get("/admin/audit-logs")
        self.assertEqual(user_res.status_code, 403, "Non-admin must be denied access to audit logs")

    # 12. Denied access records status='DENIED' in audit logs
    def test_denied_access_recorded_in_audit_logs(self):
        self._login("viewer_c", self.viewer_c_id, role="user")
        self.client.get(f"/documents/download/{self.doc_a_id}")

        conn = get_db_connection()
        log = conn.execute(
            "SELECT * FROM audit_logs WHERE action = 'UNAUTHORIZED_DOWNLOAD_ATTEMPT' ORDER BY id DESC"
        ).fetchone()
        conn.close()

        self.assertIsNotNone(log, "Denied access must create an audit log entry")
        self.assertEqual(log["status"], "DENIED", "Audit log status must record DENIED")

    # 13. CSRF protection is enforced
    def test_csrf_protection_enforced(self):
        self._login("owner_a", self.owner_a_id, role="user")
        # Omit CSRF token
        res = self.client.post(
            f"/documents/delete/{self.doc_a_id}",
            data={}
        )
        self.assertEqual(res.status_code, 403, "POST request without CSRF token must be rejected with 403")

    # 14. Health check endpoint responds healthy
    def test_health_check_endpoint(self):
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        json_data = res.get_json()
        self.assertEqual(json_data["status"], "healthy")
        self.assertEqual(json_data["app"], "TrustVault")

    # 15. SHA-256 verification detects document-content changes
    def test_sha256_verification_detects_document_tampering(self):
        from run import UPLOAD_FOLDER
        local_file = UPLOAD_FOLDER / "tampered.pdf"
        local_file.write_bytes(b"ORIGINAL CONTENT")
        original_hash = hashlib.sha256(b"ORIGINAL CONTENT").hexdigest()

        conn = get_db_connection()
        doc_id = conn.execute(
            """
            INSERT INTO documents (owner_id, original_name, stored_name, sha256_hash, file_size, category)
            VALUES (?, 'tampered.pdf', 'tampered.pdf', ?, 16, 'General')
            """,
            (self.owner_a_id, original_hash)
        ).lastrowid
        conn.commit()
        conn.close()

        # Malicious actor tampers with stored file on disk
        local_file.write_bytes(b"ALTERED / CORRUPTED FILE CONTENT")

        self._login("owner_a", self.owner_a_id, role="user")
        res = self.client.get(f"/documents/download/{doc_id}")
        self.assertEqual(res.status_code, 409, "SHA-256 hash mismatch must return 409 Conflict")

        # Cleanup
        local_file.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
