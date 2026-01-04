# models.py
from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.db.models import Q
import uuid
import random
import string
from django.utils import timezone


class Room(models.Model):
    ROOM_TYPES = [
        ("global", "Global Chat"),
        ("regional", "Regional Chat"),
        ("private", "Private Room"),
        ("local", "LAN/WiFi Local"),
        ("direct", "Direct Message"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    short_code = models.CharField(max_length=6, unique=True, blank=True, null=True)
    name = models.CharField(max_length=100, blank=True)
    room_type = models.CharField(max_length=20, choices=ROOM_TYPES, default="private")
    is_private = models.BooleanField(default=False)
    password = models.CharField(max_length=50, blank=True, null=True)
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_rooms",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    expires_in_minutes = models.IntegerField(default=60, null=True)
    is_closed = models.BooleanField(default=False)
    dm_participants = models.ManyToManyField(User, related_name="dm_rooms", blank=True)

    def __str__(self):
        return self.name or f"Room {self.short_code or str(self.id)[:8]}"

    def save(self, *args, **kwargs):
        # Generate short code if not provided
        if not self.short_code:
            self.short_code = self.generate_short_code()

        # Auto-set properties for direct message rooms
        if self.room_type == "direct":
            self.is_private = True  # Direct rooms are always private

        super().save(*args, **kwargs)

        # For direct rooms, update participants from room name if needed
        if self.room_type == "direct":
            self.update_dm_participants_from_name()

    def generate_short_code(self):
        """Generate a unique 6-character room code"""
        characters = string.ascii_uppercase + string.digits
        characters = (
            characters.replace("0", "")
            .replace("O", "")
            .replace("1", "")
            .replace("I", "")
            .replace("L", "")
        )

        while True:
            code = "".join(random.choices(characters, k=6))
            if not Room.objects.filter(short_code=code).exists():
                return code

    def update_dm_participants_from_name(self):
        """Update dm_participants from room name (for direct rooms)"""
        if self.room_type != "direct":
            return

        import re

        match = re.search(r"DM:\s*(.+?)\s*&\s*(.+)", self.name)
        if match:
            participant1_name = match.group(1).strip()
            participant2_name = match.group(2).strip()

            # Add participants
            try:
                user1 = User.objects.get(username=participant1_name)
                self.dm_participants.add(user1)
            except User.DoesNotExist:
                pass

            try:
                user2 = User.objects.get(username=participant2_name)
                self.dm_participants.add(user2)
            except User.DoesNotExist:
                pass

    def is_direct_message(self):
        """Check if this is a direct message room"""
        return self.room_type == "direct"

    def get_other_participant(self, user):
        """Get the other user in a direct message"""
        if (
            self.room_type != "direct"
            or not self.dm_participants.filter(id=user.id).exists()
        ):
            return None

        other_participants = self.dm_participants.exclude(id=user.id)
        return other_participants.first() if other_participants.exists() else None

    def can_user_access(self, user=None, session_key=None):
        """Check if user/session can access this room"""
        if self.is_closed:
            return False, "This room has been closed."

        # For DIRECT MESSAGE rooms - special access rules
        if self.room_type == "direct":
            # Only authenticated users can access direct messages
            if not user or not user.is_authenticated:
                return False, "You must be logged in to access direct messages."

            # Check if user is a participant in this direct message
            if not self.dm_participants.filter(id=user.id).exists():
                return False, "You are not a participant in this direct message."

            return True, "Access granted (direct message participant)"

        # For NON-DIRECT rooms, use regular access rules
        if not self.is_private or not self.password:
            return True, "Access granted"  # Public rooms always accessible

        # Room creator always has access
        if user and self.created_by == user:
            return True, "Access granted (room creator)"

        # Check UserRoomAccess for logged-in users
        if user:
            user_access = UserRoomAccess.objects.filter(user=user, room=self).first()
            if user_access and user_access.is_valid():
                # Verify stored hash matches current password
                import hashlib

                current_hash = hashlib.sha256(self.password.encode()).hexdigest()
                if user_access.password_hash == current_hash:
                    return True, "Access granted via saved password"
                else:
                    return False, "Room password has changed."

        return False, "Access denied"


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    avatar = models.CharField(
        max_length=50,
        default="avt1.jpg",
        choices=[
            ("avt1.jpg", "Cat"),
            ("avt2.jpg", "Dog"),
            ("avt3.jpg", "Robot"),
            ("avt4.jpg", "Ghost"),
            ("avt5.jpg", "Alien"),
        ],
    )
    description = models.TextField(max_length=500, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.user.username


class MediaView(models.Model):
    """Track which users have viewed which temporary media"""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    media = models.ForeignKey(
        "TemporaryMedia", on_delete=models.CASCADE, related_name="user_views"
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    session_key = models.CharField(max_length=255, null=True, blank=True)
    username = models.CharField(max_length=150)
    viewed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [["media", "user"], ["media", "session_key"]]
        indexes = [
            models.Index(fields=["media", "user"]),
            models.Index(fields=["media", "session_key"]),
        ]

    def __str__(self):
        return f"{self.username} viewed {self.media.id}"


# In models.py - Update TemporaryMedia model
class TemporaryMedia(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    file = models.FileField(upload_to="temp_media/%Y/%m/%d/")
    uploader_username = models.CharField(max_length=150)
    room_id = models.UUIDField()
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True)
    # Add these new fields
    media_type = models.CharField(
        max_length=10,
        choices=[("once", "View Once"), ("normal", "Normal Media")],
        default="once",
    )
    is_expired = models.BooleanField(default=False)

    def __str__(self):
        return f"Media {self.id} by {self.uploader_username} ({self.media_type})"

    def delete(self, *args, **kwargs):
        if self.file:
            self.file.delete(save=False)
        super().delete(*args, **kwargs)

    def has_user_viewed(self, user=None, session_key=None):
        """Check if a specific user/session has viewed this media"""
        if self.media_type == "normal":
            return False  # Normal media can be viewed multiple times
        if user:
            return self.user_views.filter(user=user).exists()
        elif session_key:
            return self.user_views.filter(session_key=session_key).exists()
        return False

    def mark_as_viewed_by_user(self, user=None, session_key=None, username=""):
        """Mark this media as viewed by a specific user/session"""
        if self.media_type == "normal":
            return  # Don't track views for normal media

        if user:
            MediaView.objects.get_or_create(
                media=self, user=user, defaults={"username": username}
            )
        elif session_key:
            MediaView.objects.get_or_create(
                media=self, session_key=session_key, defaults={"username": username}
            )

    def get_view_count(self):
        """Get total number of views"""
        return self.user_views.count()


class ChatMessage(models.Model):
    """Store message edits and deletions"""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    room_id = models.UUIDField(db_index=True)
    message_id = models.CharField(
        max_length=100, db_index=True
    )  # Original message ID from Redis
    username = models.CharField(max_length=150)
    original_message = models.TextField()
    edited_message = models.TextField(null=True, blank=True)
    is_deleted = models.BooleanField(default=False)
    is_edited = models.BooleanField(default=False)

    # Add these missing fields
    is_media = models.BooleanField(default=False)
    media_id = models.UUIDField(null=True, blank=True)
    filename = models.CharField(max_length=255, null=True, blank=True)
    media_type = models.CharField(
        max_length=10,
        choices=[("once", "View Once"), ("normal", "Normal Media")],
        default="once",
    )
    is_image = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True)
    deleted_by = models.CharField(max_length=150, null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["room_id", "message_id"]),
            models.Index(fields=["room_id", "username"]),
            models.Index(fields=["is_media"]),
            models.Index(fields=["media_id"]),
        ]

    def __str__(self):
        return f"{self.username}: {self.original_message[:50]}"

    def get_current_message(self):
        """Get the current message (edited or original)"""
        if self.is_deleted:
            return "[This message was deleted]"
        return self.edited_message if self.is_edited else self.original_message

    def save(self, *args, **kwargs):
        """Override save to handle empty media_id properly"""
        # Convert empty string media_id to None
        if self.media_id == "":
            self.media_id = None
        super().save(*args, **kwargs)


class ChatPoll(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    room = models.ForeignKey(Room, on_delete=models.CASCADE, related_name="polls")
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    question = models.CharField(max_length=500)
    options = models.JSONField()  # {"option1": 0, "option2": 0, ...}
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.question[:50]


class Friendship(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("accepted", "Accepted"),
        ("blocked", "Blocked"),
    ]

    from_user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="friendships_sent"
    )
    to_user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="friendships_received"
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ["from_user", "to_user"]


class Notification(models.Model):
    NOTIFICATION_TYPES = [
        ("friend_request", "Friend Request"),
        ("friend_accepted", "Friend Request Accepted"),
        ("message", "New Message"),
        ("room_invite", "Room Invite"),
        ("complaint_reply", "Complaint Reply"),
    ]

    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="notifications"
    )
    notification_type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES)
    title = models.CharField(max_length=200)
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    related_id = models.CharField(max_length=100, blank=True, null=True)

    def __str__(self):
        return f"{self.user.username}: {self.title}"


class Complaint(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("in_review", "In Review"),
        ("resolved", "Resolved"),
        ("rejected", "Rejected"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    username = models.CharField(max_length=150)
    email = models.EmailField(blank=True, null=True)
    subject = models.CharField(max_length=200)
    message = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    admin_reply = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.subject} - {self.status}"


class RoomAccess(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    room = models.ForeignKey(Room, on_delete=models.CASCADE, related_name="access_logs")
    session_key = models.CharField(max_length=255, db_index=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    username = models.CharField(max_length=150, default="Anonymous")
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, null=True)
    access_token = models.CharField(max_length=255, blank=True, null=True)
    accessed_at = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ["-accessed_at"]
        indexes = [
            models.Index(fields=["session_key", "room"]),
            models.Index(fields=["accessed_at"]),
        ]

    def __str__(self):
        return f"{self.username} accessed {self.room.name}"


class UserRoomAccess(models.Model):
    """Store which users have access to which private rooms"""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="room_accesses"
    )
    room = models.ForeignKey(
        Room, on_delete=models.CASCADE, related_name="user_accesses"
    )
    password_hash = models.CharField(max_length=255)
    granted_at = models.DateTimeField(auto_now_add=True)
    last_accessed = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ["user", "room"]
        indexes = [
            models.Index(fields=["user", "room"]),
            models.Index(fields=["expires_at"]),
        ]

    def __str__(self):
        return f"{self.user.username} -> {self.room.name}"

    def is_valid(self):
        if self.expires_at:
            return timezone.now() < self.expires_at
        return True


class UserRoomJoin(models.Model):
    """
    Tracks when a user joined/started participating in a room.
    Used to maintain stable "recently joined" lists in the sidebar.
    """

    user = models.ForeignKey("auth.User", on_delete=models.CASCADE)
    room = models.ForeignKey(Room, on_delete=models.CASCADE)
    joined_at = models.DateTimeField(default=timezone.now)

    class Meta:
        # Most recent first by default
        ordering = ["-joined_at"]
        # One join record per user-room pair
        unique_together = ["user", "room"]
        indexes = [
            models.Index(fields=["user", "-joined_at"]),
            models.Index(fields=["user", "room"]),
        ]

    def __str__(self):
        return f"{self.user.username} → {self.room} @ {self.joined_at}"


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)
