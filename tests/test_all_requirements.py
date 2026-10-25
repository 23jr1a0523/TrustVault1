"""
Comprehensive end-to-end requirement verification suite for TrustVault.
Tests all 12 points requested by the user prompt.
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from io import BytesIO
from pathlib import Path

# Set up test database path override
temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
temp_db.close()
os.environ["DATABASE_URL"] = ""
os.environ["SECRET_KEY"] = "comprehensive-test-secret-key-very-secure-32chars"

import database
database.DB_PATH = Path(temp_db.name)

from run import (
    ALLOWED_EXTENSIONS,
    UPLOAD_FOLDER,
    app,
    generate_password_hash,
    get_db_connection,
    init_db,
)


class VerifyAllRequirementsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        init_db()

    @classmethod
    def tearDownClass(cls):
        try:
            os.unlink(temp_db.name)
        except Exception:
            pass

    def setUp(self):
        self.client = app.test_client()

    def _get_csrf_token(self, client):
        """Extracts CSRF token from session or generates one for test requests."""
        with client.session_transaction() as sess:
            token = sess.get("_csrf_token")
            if not token:
                token = "test-csrf-token-12345"
                sess["_csrf_token"] = token
            return token

    # Requirement 1: Register a new user and reject duplicates
    def test_01_registration_flow_and_duplicate_prevention(self):
        # Register new user 'alice_test'
        client = app.test_client()
        csrf = self._get_csrf_token(client)
        resp = client.post(
            "/register",
            data={
                "username": "alice_test",
                "password": "AlicePassword123!",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        self.assertEqual(resp.status_code, 302, "Registration should redirect on success")
        self.assertIn("/dashboard", resp.headers["Location"], "Successful registration should redirect to dashboard")

        # Verify password is encrypted and not plaintext in database
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE LOWER(username) = LOWER('alice_test')").fetchone()
        conn.close()
        self.assertIsNotNone(user, "Registered user must exist in database")
        self.assertNotEqual(user["password_hash"], "AlicePassword123!", "Plaintext passwords must never be stored")
        self.assertTrue(
            user["password_hash"].startswith("scrypt:") or user["password_hash"].startswith("pbkdf2:"),
            "Password must be securely hashed"
        )

        # Attempt duplicate registration with the same username (case-insensitive)
        client2 = app.test_client()
        csrf2 = self._get_csrf_token(client2)
        dup_resp = client2.post(
            "/register",
            data={
                "username": "ALICE_TEST",
                "password": "AnotherPassword123!",
                "csrf_token": csrf2,
            },
            follow_redirects=True,
        )
        self.assertEqual(dup_resp.status_code, 200)
        self.assertIn("already taken", dup_resp.get_data(as_text=True).lower(), "Clear error message on duplicate registration")

    # Requirement 2: Log in using registered credentials
    def test_02_login_with_registered_credentials(self):
        client = app.test_client()
        csrf = self._get_csrf_token(client)
        resp = client.post(
            "/login",
            data={
                "username": "alice_test",
                "password": "AlicePassword123!",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        self.assertEqual(resp.status_code, 302, "Login should redirect to dashboard")
        self.assertIn("/dashboard", resp.headers["Location"])

        # Check session populated
        with client.session_transaction() as sess:
            self.assertEqual(sess.get("username"), "alice_test")
            self.assertIsNotNone(sess.get("user_id"))

    # Requirement 3: Reject invalid credentials
    def test_03_reject_invalid_credentials(self):
        client = app.test_client()
        csrf = self._get_csrf_token(client)

        # Wrong password
        resp_wrong_pw = client.post(
            "/login",
            data={
                "username": "alice_test",
                "password": "WrongPassword999!",
                "csrf_token": csrf,
            },
            follow_redirects=True,
        )
        self.assertEqual(resp_wrong_pw.status_code, 200)
        content = resp_wrong_pw.get_data(as_text=True)
        self.assertIn("incorrect password", content.lower())

        # Non-existent user
        resp_nonexistent = client.post(
            "/login",
            data={
                "username": "non_existent_ghost_user",
                "password": "Password123!",
                "csrf_token": csrf,
            },
            follow_redirects=True,
        )
        self.assertEqual(resp_nonexistent.status_code, 200)
        content_ghost = resp_nonexistent.get_data(as_text=True)
        self.assertIn("not found", content_ghost.lower())

    # Requirement 4: Upload valid document without 404 (both /documents/upload and /upload)
    def test_04_document_upload_without_404(self):
        client = app.test_client()
        csrf = self._get_csrf_token(client)
        # Log in as alice
        client.post(
            "/login",
            data={"username": "alice_test", "password": "AlicePassword123!", "csrf_token": csrf},
        )

        # Upload document via /documents/upload
        file_content_1 = b"TrustVault Confidential Specification v1.0"
        upload_resp_1 = client.post(
            "/documents/upload",
            data={
                "document": (BytesIO(file_content_1), "confidential_specs.pdf"),
                "category": "Confidential",
                "csrf_token": csrf,
            },
            content_type="multipart/form-data",
            follow_redirects=False,
        )
        self.assertEqual(upload_resp_1.status_code, 302, "Upload to /documents/upload must redirect on success without 404")
        self.assertIn("/documents", upload_resp_1.headers["Location"])

        # Upload document via alias /upload
        file_content_2 = b"TrustVault Security Audit Checklist 2026"
        upload_resp_2 = client.post(
            "/upload",
            data={
                "document": (BytesIO(file_content_2), "security_audit.pdf"),
                "category": "Legal",
                "csrf_token": csrf,
            },
            content_type="multipart/form-data",
            follow_redirects=False,
        )
        self.assertEqual(upload_resp_2.status_code, 302, "Upload to /upload alias must redirect on success without 404")
        self.assertIn("/documents", upload_resp_2.headers["Location"])

        # GET request to /upload or /documents/upload should redirect to /documents (never 404 or 405)
        get_upload_resp = client.get("/upload", follow_redirects=False)
        self.assertEqual(get_upload_resp.status_code, 302)
        get_docs_upload_resp = client.get("/documents/upload", follow_redirects=False)
        self.assertEqual(get_docs_upload_resp.status_code, 302)

    # Requirement 5: Verify document is saved and appears in user dashboard
    def test_05_document_saved_and_in_dashboard(self):
        client = app.test_client()
        csrf = self._get_csrf_token(client)
        client.post(
            "/login",
            data={"username": "alice_test", "password": "AlicePassword123!", "csrf_token": csrf},
        )

        # Check in database
        conn = get_db_connection()
        alice = conn.execute("SELECT id FROM users WHERE username = 'alice_test'").fetchone()
        docs = conn.execute("SELECT * FROM documents WHERE owner_id = ?", (alice["id"],)).fetchall()
        conn.close()
        self.assertGreaterEqual(len(docs), 2, "Uploaded documents must be persisted in database")

        # Check /documents page displays the document names and SHA-256 hashes
        doc_page_resp = client.get("/documents")
        self.assertEqual(doc_page_resp.status_code, 200)
        doc_page_html = doc_page_resp.get_data(as_text=True)
        self.assertIn("confidential_specs.pdf", doc_page_html)
        self.assertIn("security_audit.pdf", doc_page_html)

        # Check /dashboard page renders document count
        dash_resp = client.get("/dashboard")
        self.assertEqual(dash_resp.status_code, 200)
        dash_html = dash_resp.get_data(as_text=True)
        self.assertIn("Owned Documents", dash_html)

    # Requirement 6: Download document and verify byte content and SHA-256 integrity
    def test_06_download_document_and_verify_contents(self):
        client = app.test_client()
        csrf = self._get_csrf_token(client)
        client.post(
            "/login",
            data={"username": "alice_test", "password": "AlicePassword123!", "csrf_token": csrf},
        )

        conn = get_db_connection()
        doc = conn.execute("SELECT * FROM documents WHERE original_name = 'confidential_specs.pdf'").fetchone()
        conn.close()
        self.assertIsNotNone(doc)

        # Test download via /documents/download/<id>
        download_resp = client.get(f"/documents/download/{doc['id']}")
        self.assertEqual(download_resp.status_code, 200)
        self.assertEqual(download_resp.data, b"TrustVault Confidential Specification v1.0")

        # Verify cryptographic SHA-256 matches
        downloaded_hash = hashlib.sha256(download_resp.data).hexdigest()
        self.assertEqual(downloaded_hash, doc["sha256_hash"], "Downloaded file SHA-256 must match database record")

        # Test download via alias /download/<id>
        alias_resp = client.get(f"/download/{doc['id']}")
        self.assertEqual(alias_resp.status_code, 200)
        self.assertEqual(alias_resp.data, b"TrustVault Confidential Specification v1.0")

    # Requirement 7: Confirm second user cannot access first user's private documents without permission
    def test_07_second_user_cannot_access_private_documents(self):
        # Register user Bob
        client_bob = app.test_client()
        csrf_bob = self._get_csrf_token(client_bob)
        client_bob.post(
            "/register",
            data={
                "username": "bob_test",
                "password": "BobPassword123!",
                "csrf_token": csrf_bob,
            },
        )

        # Get Alice's document ID
        conn = get_db_connection()
        alice_doc = conn.execute("SELECT * FROM documents WHERE original_name = 'confidential_specs.pdf'").fetchone()
        conn.close()

        # Bob attempts unauthorized download
        unauth_resp = client_bob.get(f"/documents/download/{alice_doc['id']}")
        self.assertEqual(unauth_resp.status_code, 403, "Second user must be denied (403 Forbidden) from private docs")

        # Bob attempts unauthorized download via alias route
        unauth_alias = client_bob.get(f"/download/{alice_doc['id']}")
        self.assertEqual(unauth_alias.status_code, 403, "Second user must be denied (403 Forbidden) on alias route")

        # Alice shares document with Bob
        client_alice = app.test_client()
        csrf_alice = self._get_csrf_token(client_alice)
        client_alice.post(
            "/login",
            data={"username": "alice_test", "password": "AlicePassword123!", "csrf_token": csrf_alice},
        )
        share_resp = client_alice.post(
            f"/documents/share/{alice_doc['id']}",
            data={
                "target_username": "bob_test",
                "permission": "READ",
                "csrf_token": csrf_alice,
            },
            follow_redirects=False,
        )
        self.assertEqual(share_resp.status_code, 302, "Sharing should succeed and redirect")

        # Bob can now download the shared document
        auth_resp = client_bob.get(f"/documents/download/{alice_doc['id']}")
        self.assertEqual(auth_resp.status_code, 200, "Authorized shared viewer should now be able to download")
        self.assertEqual(auth_resp.data, b"TrustVault Confidential Specification v1.0")

    # Requirement 8: Confirm unauthenticated users cannot access protected pages
    def test_08_unauthenticated_users_redirected_to_login(self):
        unauth_client = app.test_client()
        protected_endpoints = [
            "/dashboard",
            "/documents",
            "/profile",
            "/file-integrity",
            "/access-control",
            "/admin/audit-logs",
            "/admin/users",
        ]
        for endpoint in protected_endpoints:
            resp = unauth_client.get(endpoint, follow_redirects=False)
            self.assertEqual(
                resp.status_code, 302,
                f"Unauthenticated access to {endpoint} must redirect to login"
            )
            self.assertIn("/login", resp.headers["Location"])

    # Requirement 9: Confirm normal users cannot access admin pages
    def test_09_normal_users_cannot_access_admin_pages(self):
        client = app.test_client()
        csrf = self._get_csrf_token(client)
        client.post(
            "/login",
            data={"username": "alice_test", "password": "AlicePassword123!", "csrf_token": csrf},
        )

        # Alice is role='user', should get 403 on admin routes
        for admin_endpoint in ["/admin/users", "/admin-users", "/admin/audit-logs", "/audit-logs"]:
            resp = client.get(admin_endpoint)
            self.assertEqual(
                resp.status_code, 403,
                f"Normal user access to {admin_endpoint} must be rejected with 403 Forbidden"
            )

    # Requirement 10: Confirm admin can view registered users and audit logs
    def test_10_admin_can_view_users_and_audit_logs(self):
        # Create an admin user
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES ('admin_test', ?, 'admin')",
            (generate_password_hash("AdminPass123!"),)
        )
        conn.commit()
        conn.close()

        admin_client = app.test_client()
        csrf = self._get_csrf_token(admin_client)
        admin_client.post(
            "/login",
            data={"username": "admin_test", "password": "AdminPass123!", "csrf_token": csrf},
        )

        # Admin views registered users
        users_resp = admin_client.get("/admin/users")
        self.assertEqual(users_resp.status_code, 200)
        users_html = users_resp.get_data(as_text=True)
        self.assertIn("alice_test", users_html)
        self.assertIn("bob_test", users_html)

        # Admin views audit logs
        logs_resp = admin_client.get("/admin/audit-logs")
        self.assertEqual(logs_resp.status_code, 200)
        logs_html = logs_resp.get_data(as_text=True)
        self.assertIn("Audit", logs_html)

    # Requirement 11: Verify SHA-256 file-integrity checks detect tampering
    def test_11_sha256_integrity_detects_tampering(self):
        conn = get_db_connection()
        doc = conn.execute("SELECT * FROM documents WHERE original_name = 'security_audit.pdf'").fetchone()
        conn.close()
        self.assertIsNotNone(doc)

        # Tamper with the file on disk by modifying its content
        stored_file_path = UPLOAD_FOLDER / doc["stored_name"]
        stored_file_path.write_bytes(b"MALICIOUS_TAMPERED_INJECTED_CONTENT")

        client = app.test_client()
        csrf = self._get_csrf_token(client)
        client.post(
            "/login",
            data={"username": "alice_test", "password": "AlicePassword123!", "csrf_token": csrf},
        )

        tampered_resp = client.get(f"/documents/download/{doc['id']}")
        self.assertEqual(
            tampered_resp.status_code, 409,
            "Tampered document download must return 409 Conflict due to SHA-256 integrity mismatch"
        )
        self.assertIn("integrity check failed", tampered_resp.get_data(as_text=True).lower())

    # Requirement 12: Verify application startup, dependencies, database connectivity, and health
    def test_12_startup_and_health_check(self):
        client = app.test_client()
        resp = client.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertEqual(data.get("status"), "healthy")
        self.assertEqual(data.get("app"), "TrustVault")

        # Verify file size / extension validation rejects dangerous uploads
        csrf = self._get_csrf_token(client)
        client.post(
            "/login",
            data={"username": "alice_test", "password": "AlicePassword123!", "csrf_token": csrf},
        )
        bad_ext_resp = client.post(
            "/documents/upload",
            data={
                "document": (BytesIO(b"malicious script"), "exploit.exe"),
                "csrf_token": csrf,
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(bad_ext_resp.status_code, 400, "Dangerous extensions (.exe) must be rejected with 400")


if __name__ == "__main__":
    unittest.main()
