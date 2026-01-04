# context_processors.py
# Missing imports!
from django.db.models import Q
from django.utils import timezone
from datetime import timedelta
from .models import Room, UserRoomJoin, Friendship, Notification
from chat import models


def user_rooms_context(request):
    if not request.user.is_authenticated:
        return {}

    user = request.user

    # Get friends with online status
    thirty_minutes_ago = timezone.now() - timedelta(minutes=30)

    # Get accepted friendships
    accepted_friendships = Friendship.objects.filter(
        (
            models.Q(from_user=user, status="accepted")
            | models.Q(to_user=user, status="accepted")
        )
    ).select_related("from_user", "to_user")

    # Process friends with online status
    friends_with_status = []
    for friendship in accepted_friendships:
        if friendship.from_user == user:
            friend = friendship.to_user
        else:
            friend = friendship.from_user

        # Check if friend is online (active within last 5 minutes)
        is_online = False
        if friend.last_login:
            if timezone.now() - friend.last_login < timedelta(minutes=5):
                is_online = True

        # Get friend's profile
        try:
            friend_profile = friend.profile
        except:
            from .models import Profile

            friend_profile = Profile.objects.create(user=friend)

        friends_with_status.append(
            {
                "friend": friend,
                "profile": friend_profile,
                "is_online": is_online,
                "last_seen": friend.last_login if friend.last_login else None,
            }
        )
    # ── Last 3 joined NON-DM rooms ───────────────────────────────
    recent_joins = (
        UserRoomJoin.objects.filter(user=user)
        .exclude(room__room_type="direct")
        .select_related("room")
        .order_by("-joined_at")[:3]
    )

    my_active_rooms = [join.room for join in recent_joins]

    # ── Last 3 joined/started DM conversations ───────────────────
    recent_dm_joins = (
        UserRoomJoin.objects.filter(user=user, room__room_type="direct")
        .select_related("room")
        .order_by("-joined_at")[:3]
    )

    my_recent_dms = []
    for join in recent_dm_joins:
        room = join.room
        other = room.get_other_participant(user)
        if not other:
            continue

        my_recent_dms.append(
            {
                "room": room,
                "friend": other,
                "is_online": (
                    (timezone.now() - other.last_login < timedelta(minutes=5))
                    if other.last_login
                    else False
                ),
                # Optional - you can add later:
                # "last_message_time": ...,
                # "unread_count": ...,
            }
        )

    # Optional extra counts you already have
    pending_requests = Friendship.objects.filter(to_user=user, status="pending").count()

    unread_notifications = Notification.objects.filter(user=user, is_read=False).count()

    dm_rooms_count = Room.objects.filter(
        room_type="direct", dm_participants=user, is_closed=False
    ).count()

    return {
        "my_active_rooms": my_active_rooms,
        "my_recent_dms": my_recent_dms,
        "pending_requests": pending_requests,
        "unread_notifications": unread_notifications,
        "dm_rooms_count": dm_rooms_count,
        "friends_with_status": friends_with_status[:10],  # Limit to 10 for sidebar
    }
