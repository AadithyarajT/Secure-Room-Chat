# chat/management/commands/init_room_access.py
from django.core.management.base import BaseCommand
from django.utils import timezone
from chat.models import Room, RoomAccess
from chat.utils import generate_room_access_token, hash_token


class Command(BaseCommand):
    help = "Initialize RoomAccess records for existing rooms"

    def handle(self, *args, **options):
        self.stdout.write("Initializing RoomAccess records...")

        # For each room, create access records
        rooms = Room.objects.all()

        for room in rooms:
            if room.is_private and room.password:
                self.stdout.write(f"  Room: {room.name} ({room.id})")

                # Create access for creator if exists
                if room.created_by:
                    token = generate_room_access_token()
                    RoomAccess.objects.create(
                        room=room,
                        user=room.created_by,
                        access_token=hash_token(token),
                        expires_at=timezone.now() + timezone.timedelta(days=365),
                    )
                    self.stdout.write(f"    Created creator access")

        self.stdout.write(self.style.SUCCESS("Done!"))
