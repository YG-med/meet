import json
import mimetypes
import os
import secrets
from urllib import request as urlrequest
from urllib import error as urlerror
from urllib.parse import quote


def _env(name, default=""):
    return (os.getenv(name, default) or "").strip()


def storage_configured():
    return bool(_env("SUPABASE_URL") and _env("SUPABASE_SERVICE_ROLE_KEY"))


def _base_url():
    return _env("SUPABASE_URL").rstrip("/")


def _service_key():
    return _env("SUPABASE_SERVICE_ROLE_KEY")


def _bucket():
    return _env("SUPABASE_STORAGE_BUCKET", "yujian-media")


def _headers(content_type=None):
    key = _service_key()
    headers = {
        "Authorization": f"Bearer {key}",
        "apikey": key,
    }
    if content_type:
        headers["Content-Type"] = content_type
    return headers


def ensure_bucket():
    """Create the public media bucket when Storage credentials are configured."""
    if not storage_configured():
        return False
    payload = json.dumps({
        "id": _bucket(),
        "name": _bucket(),
        "public": True,
        "file_size_limit": 5 * 1024 * 1024,
        "allowed_mime_types": ["image/png", "image/jpeg", "image/webp"],
    }).encode("utf-8")
    req = urlrequest.Request(
        f"{_base_url()}/storage/v1/bucket",
        data=payload,
        headers=_headers("application/json"),
        method="POST",
    )
    try:
        with urlrequest.urlopen(req, timeout=15):
            return True
    except urlerror.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        # Existing bucket is fine. Supabase may return 400/409 depending on API version.
        if exc.code in (400, 409) and ("already" in body.lower() or "exists" in body.lower() or "duplicate" in body.lower()):
            return True
        raise RuntimeError(f"Unable to create Supabase Storage bucket ({exc.code}): {body}") from exc


def upload_filestorage(file_storage, allowed_ext):
    if not storage_configured():
        raise RuntimeError("Supabase Storage is not configured.")
    filename = file_storage.filename or ""
    if "." not in filename:
        raise ValueError("檔案缺少副檔名")
    ext = filename.rsplit(".", 1)[1].lower()
    if ext not in allowed_ext:
        raise ValueError("僅允許 png / jpg / jpeg / webp")

    object_path = f"uploads/{secrets.token_hex(16)}.{ext}"
    data = file_storage.read()
    if len(data) > 5 * 1024 * 1024:
        raise ValueError("圖片不可超過 5MB")

    content_type = file_storage.mimetype or mimetypes.guess_type(filename)[0] or "application/octet-stream"
    encoded_path = quote(object_path, safe="/")
    req = urlrequest.Request(
        f"{_base_url()}/storage/v1/object/{quote(_bucket(), safe='')}/{encoded_path}",
        data=data,
        headers={**_headers(content_type), "x-upsert": "false"},
        method="POST",
    )
    try:
        with urlrequest.urlopen(req, timeout=30):
            pass
    except urlerror.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        raise RuntimeError(f"Supabase Storage upload failed ({exc.code}): {body}") from exc

    return f"{_base_url()}/storage/v1/object/public/{quote(_bucket(), safe='')}/{encoded_path}"
