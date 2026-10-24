import os
import mimetypes
import logging
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

def _clean_str(val: Optional[str]) -> str:
    """Strips accidental quotes and surrounding whitespace."""
    if not val:
        return ""
    val = str(val).strip()
    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
        val = val[1:-1].strip()
    return val

def _clean_jwt(key: Optional[str]) -> str:
    """Strips quotes and accidental 'Bearer ' prefix from JWT tokens."""
    key = _clean_str(key)
    if key.lower().startswith("bearer "):
        key = key[7:].strip()
    return key

def get_supabase_url() -> str:
    return _clean_str(os.environ.get("SUPABASE_URL", ""))

def get_supabase_key() -> str:
    key = (
        os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
        or os.environ.get("SUPABASE_KEY")
        or os.environ.get("SUPABASE_SERVICE_KEY")
        or ""
    )
    return _clean_jwt(key)

def get_supabase_bucket() -> str:
    bucket = _clean_str(os.environ.get("SUPABASE_BUCKET", "trustvault-documents"))
    return bucket or "trustvault-documents"

_supabase_client = None


def get_supabase_client():
    """
    Returns an authenticated Supabase client using the service role key.
    The service role key is strictly used server-side only.
    """
    global _supabase_client
    if _supabase_client is not None:
        return _supabase_client

    url = get_supabase_url()
    key = get_supabase_key()

    if not url or not key:
        logger.warning(
            "Supabase credentials not configured (SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY missing)."
        )
        return None

    # Validate that key looks like a genuine 3-part JWT token (header.payload.signature)
    parts = key.split(".")
    if len(parts) != 3:
        logger.warning(
            f"SUPABASE_SERVICE_ROLE_KEY format invalid (found {len(parts)} parts, expected 3). "
            "Please ensure you copied the JWT secret key starting with 'eyJ...' from Supabase Project Settings -> API."
        )
        return None

    try:
        from supabase import create_client
        _supabase_client = create_client(url, key)
        return _supabase_client
    except Exception as e:
        logger.error(f"Failed to initialize Supabase client: {e}")
        return None


def is_storage_configured() -> bool:
    """Checks whether valid Supabase Storage credentials are present."""
    url = get_supabase_url()
    key = get_supabase_key()
    return bool(
        url
        and key
        and not url.startswith("https://your-project-id")
        and len(key.split(".")) == 3
    )


def ensure_bucket_exists(bucket_name: Optional[str] = None) -> bool:
    """
    Ensures that the private storage bucket exists on Supabase.
    If it does not exist, creates it as a strictly PRIVATE bucket.
    """
    client = get_supabase_client()
    if not client:
        return False

    bucket = bucket_name or get_supabase_bucket()

    try:
        buckets = client.storage.list_buckets()
        existing_names = [b.name for b in buckets] if buckets else []

        if bucket not in existing_names:
            logger.info(f"Creating private Supabase storage bucket: '{bucket}'")
            client.storage.create_bucket(
                bucket,
                options={
                    "public": False,  # MUST remain private: never public!
                    "file_size_limit": 5 * 1024 * 1024,  # 5 MB limit
                    "allowed_mime_types": [
                        "application/pdf",
                        "text/plain",
                        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        "image/png",
                        "image/jpeg",
                    ],
                },
            )
            logger.info(f"Private bucket '{bucket}' created successfully.")
        return True
    except Exception as e:
        logger.warning(f"Note on ensuring bucket '{bucket}': {e}")
        return False


def upload_document_to_supabase(
    file_bytes: bytes,
    storage_path: str,
    original_filename: str,
    content_type: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Uploads file bytes to the private Supabase storage bucket.
    Uses unique server-generated storage paths (e.g., owner_id/uuid.ext).

    Returns:
        (success: bool, error_message_or_path: str)
    """
    client = get_supabase_client()
    if not client:
        return False, "Supabase Storage client is not configured or key is invalid."

    bucket = get_supabase_bucket()

    # Determine content type if not provided
    if not content_type:
        content_type, _ = mimetypes.guess_type(original_filename)
        if not content_type:
            content_type = "application/octet-stream"

    try:
        # Upload using Supabase storage client
        response = client.storage.from_(bucket).upload(
            path=storage_path,
            file=file_bytes,
            file_options={
                "content-type": content_type,
                "upsert": "true",  # Allow safe upsert
            },
        )
        return True, storage_path
    except Exception as e:
        logger.error(f"Supabase upload error for path '{storage_path}': {e}")
        return False, str(e)


def create_signed_download_url(
    storage_path: str,
    expires_in_seconds: int = 60,
) -> Optional[str]:
    """
    Generates a temporary, short-lived signed download URL for private files.
    Only to be called AFTER user authentication and authorization checks.
    Defaults to 60 seconds expiry to minimize exposure.
    """
    client = get_supabase_client()
    if not client:
        return None

    bucket = get_supabase_bucket()

    try:
        res = client.storage.from_(bucket).create_signed_url(
            storage_path,
            expires_in=expires_in_seconds,
        )
        if isinstance(res, dict):
            return res.get("signedURL") or res.get("signedUrl")
        return None
    except Exception as e:
        logger.error(f"Error creating signed URL for '{storage_path}': {e}")
        return None


def download_document_from_supabase(storage_path: str) -> Optional[bytes]:
    """
    Downloads file bytes directly from Supabase Storage to the server.
    Used for on-server SHA-256 integrity verification and secure streaming.
    """
    client = get_supabase_client()
    if not client:
        return None

    bucket = get_supabase_bucket()

    try:
        data = client.storage.from_(bucket).download(storage_path)
        return data
    except Exception as e:
        logger.error(f"Error downloading document '{storage_path}' from Supabase: {e}")
        return None


def delete_document_from_supabase(storage_path: str) -> bool:
    """
    Deletes a document object from Supabase Storage.
    Only called AFTER verifying document ownership or admin authorization.
    """
    client = get_supabase_client()
    if not client:
        return False

    bucket = get_supabase_bucket()

    try:
        client.storage.from_(bucket).remove([storage_path])
        return True
    except Exception as e:
        logger.error(f"Error deleting object '{storage_path}' from Supabase: {e}")
        return False
