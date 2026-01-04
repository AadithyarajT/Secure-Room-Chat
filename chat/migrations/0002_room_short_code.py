# Create file: chat/migrations/0002_room_short_code.py
from django.db import migrations
import random
import string


def generate_short_code():
    characters = string.ascii_uppercase + string.digits
    characters = (
        characters.replace("0", "")
        .replace("O", "")
        .replace("1", "")
        .replace("I", "")
        .replace("L", "")
    )
    return "".join(random.choices(characters, k=6))


def add_short_codes(apps, schema_editor):
    Room = apps.get_model("chat", "Room")

    for room in Room.objects.filter(short_code__isnull=True):
        # Generate unique code
        while True:
            code = generate_short_code()
            if not Room.objects.filter(short_code=code).exists():
                room.short_code = code
                room.save()
                break


class Migration(migrations.Migration):
    dependencies = [
        ("chat", "0001_initial"),  # Your initial migration
    ]

    operations = [
        migrations.RunPython(add_short_codes),
    ]
