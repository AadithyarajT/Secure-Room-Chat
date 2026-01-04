from django.core.management.base import BaseCommand
from django.utils import timezone
from chat.models import Message


class Command(BaseCommand):
    help = "Delete expired messages"

    def handle(self, *args, **options):
        deleted_count = Message.objects.filter(expires_at__lt=timezone.now()).delete()[
            0
        ]

        self.stdout.write(
            self.style.SUCCESS(f"Deleted {deleted_count} expired messages")
        )
