# chat/utils.py
import secrets
import hashlib
import base64
import uuid as uuid_lib
import json
from datetime import datetime, timedelta
from django.utils import timezone
from django.conf import settings


def generate_secure_token(length: int = 32) -> str:
    random_bytes = secrets.token_bytes(length)
    token = base64.urlsafe_b64encode(random_bytes).decode("ascii")
    return token.rstrip("=")


def generate_room_access_token() -> str:
    random_uuid = str(uuid_lib.uuid4())
    return f"room_{random_uuid}"


def hash_token(token: str) -> str:
    pepper = getattr(settings, "SECRET_PEPPER", "")
    return hashlib.sha256((token + pepper).encode()).hexdigest()


def verify_token(stored_hash: str, provided_token: str) -> bool:
    pepper = getattr(settings, "SECRET_PEPPER", "")
    provided_hash = hashlib.sha256((provided_token + pepper).encode()).hexdigest()
    return secrets.compare_digest(stored_hash, provided_hash)


def create_room_access_data(room_id: str, is_creator: bool = False):
    token = generate_room_access_token()

    if is_creator:
        expiry_days = 365
    else:
        expiry_days = 7

    return {
        "access_token": token,
        "room_id": room_id,
        "granted_at": timezone.now().isoformat(),
        "expires_at": (timezone.now() + timedelta(days=expiry_days)).isoformat(),
        "is_creator": is_creator,
        "token_hash": hash_token(token),
    }


def is_access_valid(access_data) -> bool:
    if not access_data:
        return False

    expires_at_str = access_data.get("expires_at")
    if not expires_at_str:
        return False

    try:
        expires_at = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
        return timezone.now() < expires_at
    except (ValueError, AttributeError):
        return False


def generate_random_password(length: int = 12) -> str:
    uppercase = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    lowercase = "abcdefghijkmnopqrstuvwxyz"
    digits = "23456789"
    symbols = "!@#$%^&*"

    password = [
        secrets.choice(uppercase),
        secrets.choice(lowercase),
        secrets.choice(digits),
        secrets.choice(symbols),
    ]

    all_chars = uppercase + lowercase + digits + symbols
    password.extend(secrets.choice(all_chars) for _ in range(length - 4))

    secrets.SystemRandom().shuffle(password)
    return "".join(password)


def generate_room_code() -> str:
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    code = "".join(secrets.choice(chars) for _ in range(6))

    offensive_patterns = ["BAD", "XXX", "666", "ASS", "FUC", "SEX"]
    for pattern in offensive_patterns:
        if pattern in code:
            return generate_room_code()

    return code


def get_session_room_access(request, room_id: str):
    session_key = f"room_access_{room_id}"
    return request.session.get(session_key)


def set_session_room_access(request, room_id: str, access_data):
    session_key = f"room_access_{room_id}"
    request.session[session_key] = access_data
    request.session.modified = True


def remove_session_room_access(request, room_id: str):
    session_key = f"room_access_{room_id}"
    if session_key in request.session:
        del request.session[session_key]
        request.session.modified = True


def format_time_ago(dt):
    if not dt:
        return "Never"

    now = timezone.now()
    diff = now - dt

    if diff.days > 365:
        years = diff.days // 365
        return f"{years} year{'s' if years > 1 else ''} ago"
    elif diff.days > 30:
        months = diff.days // 30
        return f"{months} month{'s' if months > 1 else ''} ago"
    elif diff.days > 0:
        return f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
    elif diff.seconds > 3600:
        hours = diff.seconds // 3600
        return f"{hours} hour{'s' if hours > 1 else ''} ago"
    elif diff.seconds > 60:
        minutes = diff.seconds // 60
        return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
    else:
        return "Just now"


def is_valid_uuid(uuid_string: str) -> bool:
    try:
        uuid_lib.UUID(uuid_string)
        return True
    except ValueError:
        return False
