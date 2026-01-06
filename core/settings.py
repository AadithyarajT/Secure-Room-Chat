import os
from pathlib import Path
from django.contrib.messages import constants as messages
from datetime import timedelta
from celery.schedules import crontab 


BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = "your-secret-key-here"  # Change this!
DEBUG = True
ALLOWED_HOSTS = ["localhost", "127.0.0.1"]

INSTALLED_APPS = [
    "daphne",  # For ASGI/WebSockets
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "corsheaders",  # Add this for CORS support
    "channels",
    "chat",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "corsheaders.middleware.CorsMiddleware",  # Add this
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "core.urls"

# core/settings.py

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "chat.context_processors.user_rooms_context",  # ADD THIS LINE
            ],
        },
    },
]
# ASGI for WebSockets
ASGI_APPLICATION = "core.asgi.application"

# Database (PostgreSQL later – SQLite for now to test fast)
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "simplechat_db",  # Your DB name
        "USER": "simplechat_users",
        "PASSWORD": "chat123",
        "HOST": "localhost",
        "PORT": "5432",
    }
}
# Channels (Redis for real-time)
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [("127.0.0.1", 6379)],
        },
    },
}
CHANNEL_LAYERS = {"default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}}


# Static files
STATIC_URL = "/static/"
STATICFILES_DIRS = [BASE_DIR / "static"]  # Add this folder later

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


STATIC_ROOT = BASE_DIR / "staticfiles"
MEDIA_URL = "/media/"
MEDIA_ROOT = os.path.join(BASE_DIR, "media")

CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

CSRF_COOKIE_SECURE = False
CSRF_COOKIE_HTTPONLY = False
CSRF_TRUSTED_ORIGINS = ["http://localhost:8000", "http://127.0.0.1:8000"]

# CORS settings
CORS_ALLOW_ALL_ORIGINS = True  # For development only
CORS_ALLOW_CREDENTIALS = True

# File upload settings
DATA_UPLOAD_MAX_MEMORY_SIZE = 10485760  # 10MB
FILE_UPLOAD_MAX_MEMORY_SIZE = 10485760  # 10MB


os.makedirs(os.path.join(MEDIA_ROOT, "temp_media"), exist_ok=True)

MESSAGE_TAGS = {
    messages.SUCCESS: "success",
    messages.ERROR: "error",
    messages.WARNING: "warning",
    messages.INFO: "info",
    messages.DEBUG: "debug",
}

SECRET_PEPPER = "your-secret-pepper-here-change-this"

# In core/settings.py
# Replace YOUR_COMPUTER_IP with the IP from Step 1
COMPUTER_IP = "192.168.1.6"  # ← Your actual IP from Step 1

ALLOWED_HOSTS = [
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    COMPUTER_IP,  # Your computer's IP
]

# Update CSRF_TRUSTED_ORIGINS
CSRF_TRUSTED_ORIGINS = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    f"http://{COMPUTER_IP}:8000",  # Your computer's IP:8000
]

CELERY_BROKER_URL = "redis://localhost:6379/1"  # Use different DB than chat
CELERY_RESULT_BACKEND = "redis://localhost:6379/1"
CELERY_ACCEPT_CONTENT = ["application/json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_TIMEZONE = "UTC"

# In settings.py
CELERY_BEAT_SCHEDULE = {
    "cleanup-expired-media": {
        "task": "chat.tasks.cleanup_expired_media",
        "schedule": crontab(hour=3, minute=0),  # Daily at 3 AM
    },
}
