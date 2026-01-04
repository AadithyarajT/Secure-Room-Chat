# chat/management/commands/cleanup_media.py
from django.core.management.base import BaseCommand
from django.utils import timezone
from chat.models import TemporaryMedia
import os


class Command(BaseCommand):
    help = "Clean up expired view-once media files"

    def handle(self, *args, **kwargs):
        # Find expired view-once media
        expired_media = TemporaryMedia.objects.filter(
            media_type="once", expires_at__lt=timezone.now()
        )

        count = expired_media.count()

        for media in expired_media:
            # Delete the file
            if media.file:
                media.file.delete(save=False)
            # Delete the database record
            media.delete()

        self.stdout.write(
            self.style.SUCCESS(f"Successfully cleaned up {count} expired media files")
        )
