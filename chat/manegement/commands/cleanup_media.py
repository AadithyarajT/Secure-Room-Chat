# chat/management/commands/cleanup_media.py
from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from chat.models import TemporaryMedia


class Command(BaseCommand):
    help = "Clean up old temporary media files"

    def add_arguments(self, parser):
        parser.add_argument(
            "--hours",
            type=int,
            default=24,
            help="Delete media older than this many hours (default: 24)",
        )

    def handle(self, *args, **options):
        hours = options["hours"]
        cutoff_time = timezone.now() - timedelta(hours=hours)

        # Find media older than specified hours
        old_media = TemporaryMedia.objects.filter(created_at__lt=cutoff_time)
        count = old_media.count()

        self.stdout.write(f"Found {count} media files older than {hours} hours")

        # Delete them
        deleted_count = 0
        for media in old_media:
            try:
                media.delete()
                deleted_count += 1
            except Exception as e:
                self.stderr.write(f"Error deleting media {media.id}: {e}")

        self.stdout.write(
            self.style.SUCCESS(f"Successfully deleted {deleted_count} media files")
        )
