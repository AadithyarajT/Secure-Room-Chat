# views.py - COMPLETE UPDATED VERSION
import mimetypes
import os
import random
import uuid
import hashlib
import redis
import json
from datetime import timedelta, datetime

# Django imports
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.forms import AuthenticationForm
from django.views.decorators.http import require_POST, require_safe
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponse, FileResponse
from django.db.models import Q
from django.utils import timezone
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash

# Local imports
from .models import (
    TemporaryMedia,
    Room,
    Profile,
    Friendship,
    Notification,
    Complaint,
    ChatPoll,
    RoomAccess,
    UserRoomAccess,
    MediaView,
    UserRoomJoin,
    ChatMessage,  # Add this line - it was missing!
)
from .forms import RegisterForm
from .utils import generate_random_password


def index(request):
    """Simple homepage with navigation"""
    register_form = RegisterForm()
    login_form = AuthenticationForm()

    # Calculate stats for the dashboard
    active_users = User.objects.filter(
        last_login__gte=timezone.now() - timedelta(hours=1)
    ).count()

    # Only count non-direct rooms
    active_rooms = Room.objects.filter(
        is_closed=False, room_type__in=["global", "regional", "private", "local"]
    ).count()

    total_messages = 0

    # Only show non-direct rooms
    recent_rooms = Room.objects.filter(
        is_closed=False, room_type__in=["global", "regional", "private", "local"]
    ).order_by("-created_at")[:5]

    # Initialize context
    context = {
        "register_form": register_form,
        "login_form": login_form,
        "active_users": active_users,
        "active_rooms": active_rooms,
        "total_messages": total_messages,
        "recent_rooms": recent_rooms,
    }

    if request.method == "POST":
        action = request.POST.get("action")

        if action == "register":
            register_form = RegisterForm(request.POST)
            if register_form.is_valid():
                user = register_form.save()
                username = register_form.cleaned_data["username"]
                user.username = username
                user.save()
                login(request, user)
                return redirect("/")

        elif action == "login":
            login_form = AuthenticationForm(request, data=request.POST)
            if login_form.is_valid():
                username = login_form.cleaned_data["username"]
                password = login_form.cleaned_data["password"]
                user = authenticate(request, username=username, password=password)
                if user:
                    login(request, user)
                    return redirect("/")

        elif action == "create_room":
            name = request.POST.get("room_name", f"Room {str(uuid.uuid4())[:8]}")
            is_private = request.POST.get("is_private") == "on"
            password = request.POST.get("password", "") if is_private else None
            room_type = request.POST.get("room_type", "private")

            # Don't allow creating DM rooms from index
            if room_type == "direct":
                messages.error(request, "Cannot create direct messages from here.")
                return redirect("index")

            # Create room
            room = Room.objects.create(
                name=name,
                room_type=room_type,
                is_private=is_private,
                password=password,
                created_by=request.user if request.user.is_authenticated else None,
            )
            if request.user.is_authenticated:
                UserRoomJoin.objects.update_or_create(
                    user=request.user, room=room, defaults={"joined_at": timezone.now()}
                )
            # If room is private and user is logged in, save access
            if is_private and password and request.user.is_authenticated:
                password_hash = hashlib.sha256(password.encode()).hexdigest()
                UserRoomAccess.objects.create(
                    user=request.user,
                    room=room,
                    password_hash=password_hash,
                    expires_at=timezone.now() + timedelta(days=365),
                )

            # If room is private, store password in session
            if is_private and password:
                if "private_rooms" not in request.session:
                    request.session["private_rooms"] = {}
                request.session["private_rooms"][str(room.id)] = password
                request.session.modified = True

            # Redirect to room with password in URL if private
            if is_private and password:
                return redirect(
                    f"/chat/{room.short_code or room.id}/?password={password}"
                )
            else:
                return redirect(f"/chat/{room.short_code or room.id}/")

    # Add user-specific context if authenticated
    if request.user.is_authenticated:
        # Get user's recent friends
        friendships = Friendship.objects.filter(
            Q(from_user=request.user, status="accepted")
            | Q(to_user=request.user, status="accepted")
        )[:5]

        recent_friends = []
        for friendship in friendships:
            if friendship.from_user == request.user:
                friend = friendship.to_user
            else:
                friend = friendship.from_user

            try:
                friend_profile = Profile.objects.get(user=friend)
            except Profile.DoesNotExist:
                friend_profile = Profile.objects.create(user=friend)

            recent_friends.append(
                {
                    "friend": friend,
                    "friend_profile": friend_profile,
                    "is_online": friend.last_login
                    and (timezone.now() - friend.last_login) < timedelta(minutes=5),
                }
            )

        pending_requests = Friendship.objects.filter(
            to_user=request.user, status="pending"
        ).count()

        unread_notifications = Notification.objects.filter(
            user=request.user, is_read=False
        ).count()

        # Count user's DM rooms
        dm_rooms_count = Room.objects.filter(
            room_type="direct", dm_participants=request.user, is_closed=False
        ).count()

        user_rooms = Room.objects.filter(
            Q(created_at__gte=timezone.now() - timedelta(days=30))
        ).count()

        user_friends = Friendship.objects.filter(
            Q(from_user=request.user, status="accepted")
            | Q(to_user=request.user, status="accepted")
        ).count()

        user_complaints = Complaint.objects.filter(
            Q(user=request.user) | Q(username=request.user.username)
        ).count()

        user_messages = 0

        context.update(
            {
                "recent_friends": recent_friends,
                "pending_requests": pending_requests,
                "unread_notifications": unread_notifications,
                "dm_rooms_count": dm_rooms_count,
                "user_rooms": user_rooms,
                "user_friends": user_friends,
                "user_messages": user_messages,
                "user_complaints": user_complaints,
            }
        )
    else:
        context.update(
            {
                "recent_friends": [],
                "pending_requests": 0,
                "unread_notifications": 0,
                "dm_rooms_count": 0,
                "user_rooms": 0,
                "user_friends": 0,
                "user_messages": 0,
                "user_complaints": 0,
            }
        )

    if request.user.is_authenticated:
        # Get user's active rooms (non-DM rooms they have access to)
        my_active_rooms = []

        # Get rooms user has accessed recently
        recent_access = RoomAccess.objects.filter(
            user=request.user,
            room__is_closed=False,
            room__room_type__in=["global", "regional", "private", "local"],
        ).order_by("-last_activity")[:5]

        for access in recent_access:
            if access.room not in my_active_rooms:
                my_active_rooms.append(access.room)

        # Also check UserRoomAccess
        user_room_access = UserRoomAccess.objects.filter(
            user=request.user,
            room__is_closed=False,
            room__room_type__in=["global", "regional", "private", "local"],
        ).select_related("room")

        for access in user_room_access:
            if access.room not in my_active_rooms:
                my_active_rooms.append(access.room)

        # Get recent DMs
        my_recent_dms = []
        dm_rooms = Room.objects.filter(
            room_type="direct", dm_participants=request.user, is_closed=False
        ).order_by("-created_at")[:5]

        for room in dm_rooms:
            # Get the other participant
            other_participants = room.dm_participants.exclude(id=request.user.id)
            if other_participants.exists():
                friend = other_participants.first()

                # Check if friend is online
                is_online = False
                if friend.last_login:
                    if timezone.now() - friend.last_login < timedelta(minutes=5):
                        is_online = True

                # Get last message time
                last_message_time = None
                try:
                    r = redis.Redis(
                        host="localhost", port=6379, db=0, decode_responses=True
                    )
                    messages_key = f"messages_{room.id}"
                    last_msg_json = r.lindex(messages_key, 0)

                    if last_msg_json:
                        last_msg = json.loads(last_msg_json)
                        last_message_time = last_msg.get("timestamp")

                        if last_message_time:
                            dt = datetime.fromtimestamp(last_message_time)
                            last_message_time = dt.strftime("%I:%M %p")
                except:
                    pass

                my_recent_dms.append(
                    {
                        "room": room,
                        "friend": friend,
                        "is_online": is_online,
                        "last_message_time": last_message_time,
                        "unread_count": 0,  # You can implement unread count later
                    }
                )

        # Add to context
        context.update(
            {
                "my_active_rooms": my_active_rooms[:5],  # Limit to 5 rooms
                "my_recent_dms": my_recent_dms,
            }
        )

    return render(request, "index.html", context)


def save_room_access(request, room):
    """Save room access for the user"""
    # Save to UserRoomAccess for logged-in users
    if request.user.is_authenticated:
        if room.password:  # Only save password if room has one
            password_hash = hashlib.sha256(room.password.encode()).hexdigest()
            UserRoomAccess.objects.update_or_create(
                user=request.user,
                room=room,
                defaults={
                    "password_hash": password_hash,
                    "expires_at": timezone.now() + timedelta(days=30),
                },
            )

    # Save to session for all users (for non-DM rooms with passwords)
    if room.room_type != "direct" and room.password:
        if "private_rooms" not in request.session:
            request.session["private_rooms"] = {}
        request.session["private_rooms"][str(room.id)] = room.password
        request.session.modified = True


def render_room(request, room, username):
    """Render the chat room"""
    # Log the access
    try:
        RoomAccess.objects.create(
            room=room,
            session_key=(
                request.session.session_key if not request.user.is_authenticated else ""
            ),
            user=request.user if request.user.is_authenticated else None,
            username=username,
            ip_address=request.META.get("REMOTE_ADDR", ""),
            user_agent=request.META.get("HTTP_USER_AGENT", "")[:200],
            is_active=True,
        )
    except Exception as e:
        print(f"Error logging room access: {e}")

    return render(
        request,
        "chat.html",
        {
            "room_id": str(room.id),
            "short_code": room.short_code or "",
            "room_name": room.name or f"Room {room.short_code or str(room.id)[:8]}",
            "username": username,
            "is_dm": room.room_type == "direct",
        },
    )


def show_password_form(request, room, error=None):
    """Show password entry form"""
    return render(
        request,
        "private_room_password.html",
        {
            "room_id": room.short_code or str(room.id),
            "room_name": room.name or "Private Room",
            "is_short_code": bool(room.short_code),
            "error": error,
            "can_save_password": request.user.is_authenticated,
        },
    )


def room_view(request, room_id):
    """Main room view with comprehensive access control"""
    try:
        # Try as UUID first
        try:
            room_uuid = uuid.UUID(room_id)
            room = Room.objects.get(id=room_uuid)
        except ValueError:
            # Try as short code
            room = Room.objects.get(short_code=room_id.upper())
    except Room.DoesNotExist:
        return HttpResponse("Room not found", status=404)

    # Check if room is closed
    if room.is_closed:
        return HttpResponse("This room has been closed.", status=410)

    # STRICT DM ACCESS CONTROL
    if room.room_type == "direct":
        if not request.user.is_authenticated:
            return HttpResponse(
                "You must be logged in to access direct messages.", status=403
            )

        # Check if user is a participant - FIXED VERSION
        # First check dm_participants ManyToMany field
        is_participant = room.dm_participants.filter(id=request.user.id).exists()

        # Also check UserRoomAccess as fallback
        if not is_participant:
            user_access = UserRoomAccess.objects.filter(
                user=request.user, room=room
            ).first()
            if user_access and user_access.is_valid():
                is_participant = True
                # Add to dm_participants for future
                room.dm_participants.add(request.user)

        if not is_participant:
            return HttpResponse(
                "You are not a participant in this direct message.", status=403
            )

        # Get username
    # For non-DM rooms, use existing access control
    # Get username
        username = request.user.username if request.user.is_authenticated else "Anonymous"        
        
        
        return render_room(request, room, username)

    # For non-DM rooms, use existing access control
    # ... rest of your existing code for non-DM rooms ...
    # For non-DM rooms, use existing access control
    # Get username
    username = request.user.username if request.user.is_authenticated else "Anonymous"

    # Get password from URL if provided
    password_from_url = request.GET.get("password")

    # Check access for non-DM rooms
    if room.is_private and room.password:
        # For ALL users (logged in or not), check URL password first
        if password_from_url:
            if password_from_url == room.password:
                # Password correct - save access based on user type
                save_room_access(request, room)
                return render_room(request, room, username)
            else:
                # Wrong password
                return show_password_form(request, room, "Incorrect password")

        # Check if user already has access
        # For logged-in users: check UserRoomAccess
        if request.user.is_authenticated:
            user_access = UserRoomAccess.objects.filter(
                user=request.user, room=room
            ).first()

            if user_access and user_access.is_valid():
                # Verify stored hash matches current password
                stored_hash = user_access.password_hash
                current_hash = hashlib.sha256(room.password.encode()).hexdigest()
                if stored_hash == current_hash:
                    # Access is valid - continue to chat
                    return render_room(request, room, username)
                else:
                    # Password changed - show password form
                    return show_password_form(
                        request,
                        room,
                        "Room password has changed. Please enter new password.",
                    )

        # For all users: check session storage
        private_rooms = request.session.get("private_rooms", {})
        stored_password = private_rooms.get(str(room.id))

        if stored_password == room.password:
            # Session has valid password - if logged in, also save to UserRoomAccess
            if request.user.is_authenticated:
                save_room_access(request, room)
            return render_room(request, room, username)

        # No saved access anywhere - show password form
        return show_password_form(request, room)

    # If room is not private, allow access
    return render_room(request, room, username)


def rooms_view(request):
    """Room management page - EXCLUDES DM ROOMS"""
    # Only show non-DM rooms
    active_rooms = Room.objects.filter(
        is_closed=False, room_type__in=["global", "regional", "private", "local"]
    ).count()

    recent_rooms = Room.objects.filter(
        is_closed=False, room_type__in=["global", "regional", "private", "local"]
    ).order_by("-created_at")[:12]

    active_users = User.objects.filter(
        last_login__gte=timezone.now() - timedelta(hours=1)
    ).count()

    total_messages = 0

    context = {
        "active_rooms": active_rooms,
        "recent_rooms": recent_rooms,
        "active_users": active_users,
        "total_messages": total_messages,
    }

    if request.user.is_authenticated:
        context["pending_requests"] = Friendship.objects.filter(
            to_user=request.user, status="pending"
        ).count()
        context["unread_notifications"] = Notification.objects.filter(
            user=request.user, is_read=False
        ).count()

    # Handle room creation
    if request.method == "POST":
        action = request.POST.get("action")

        if action == "create_room":
            name = request.POST.get("room_name", f"Room {str(uuid.uuid4())[:8]}")
            is_private = request.POST.get("is_private") == "on"
            password = request.POST.get("password", "") if is_private else None
            room_type = request.POST.get("room_type", "private")

            # Don't allow creating DM rooms from this page
            if room_type == "direct":
                messages.error(request, "Cannot create direct messages from here.")
                return redirect("rooms")

            # Generate password if private and not provided
            if is_private and not password:
                password = generate_random_password(10)

            # Create room
            room = Room.objects.create(
                name=name,
                room_type=room_type,
                is_private=is_private,
                password=password,
                created_by=request.user if request.user.is_authenticated else None,
            )
            if request.user.is_authenticated:
                UserRoomJoin.objects.update_or_create(
                    user=request.user, room=room, defaults={"joined_at": timezone.now()}
                )
            # If user is logged in and created private room, save access
            if request.user.is_authenticated and is_private and password:
                password_hash = hashlib.sha256(password.encode()).hexdigest()
                UserRoomAccess.objects.create(
                    user=request.user,
                    room=room,
                    password_hash=password_hash,
                    expires_at=timezone.now() + timedelta(days=365),
                )

            # Redirect to room
            if is_private and password:
                return redirect(
                    f"/chat/{room.short_code or room.id}/?password={password}"
                )
            else:
                return redirect(f"/chat/{room.short_code or room.id}/")

    return render(request, "rooms.html", context)


# In views.py - Update upload_once_view_media function and add new functions


@csrf_exempt
@require_POST
def upload_media(request):
    """Handle both normal and view-once media uploads"""
    if not request.session.session_key:
        request.session.create()

    file = request.FILES.get("file")
    room_id = request.POST.get("room_id")
    media_type = request.POST.get("media_type", "once")  # New: once or normal

    if not file or not room_id:
        return JsonResponse({"error": "Missing file or room"}, status=400)

    try:
        room = Room.objects.get(id=room_id)
        if room.is_closed:
            return JsonResponse({"error": "Room is closed"}, status=410)
    except Room.DoesNotExist:
        return JsonResponse({"error": "Room not found"}, status=404)

    MAX_SIZE = 10 * 1024 * 1024
    if file.size > MAX_SIZE:
        return JsonResponse({"error": "File too large (max 10MB)"}, status=400)

    ext = os.path.splitext(file.name)[1].lower()
    allowed_extensions = [
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".mp4",
        ".mov",
        ".webm",
        ".webp",
        ".avi",
    ]
    if ext not in allowed_extensions:
        return JsonResponse({"error": "File type not allowed"}, status=400)

    username = request.user.username if request.user.is_authenticated else "Anonymous"

    # Calculate expiry for view-once media
    expires_at = None
    if media_type == "once":
        expires_at = timezone.now() + timedelta(hours=24)

    media = TemporaryMedia.objects.create(
        file=file,
        uploader_username=username,
        room_id=room.id,
        media_type=media_type,
        expires_at=expires_at,
    )

    return JsonResponse(
        {
            "status": "ok",
            "media_id": str(media.id),
            "filename": file.name,
            "is_image": ext in [".jpg", ".jpeg", ".png", ".gif", ".webp"],
            "media_type": media_type,
            "expires_at": expires_at.isoformat() if expires_at else None,
        }
    )


@csrf_exempt
@require_POST
def get_media_for_view(request, media_id):
    """Check if user can view this media"""
    try:
        media = get_object_or_404(TemporaryMedia, id=media_id)

        # Check if media is expired (only for view-once)
        if (
            media.media_type == "once"
            and media.expires_at
            and timezone.now() > media.expires_at
        ):
            return JsonResponse(
                {"status": "error", "message": "This media has expired."},
                status=410,
            )

        # Get username for logging
        username = (
            request.user.username if request.user.is_authenticated else "Anonymous"
        )

        # Check if user has already viewed this media (only for view-once)
        if media.media_type == "once":
            if request.user.is_authenticated:
                has_viewed = media.has_user_viewed(user=request.user)
            else:
                if not request.session.session_key:
                    request.session.create()
                has_viewed = media.has_user_viewed(
                    session_key=request.session.session_key
                )

            if has_viewed:
                return JsonResponse(
                    {
                        "status": "error",
                        "message": "You have already viewed this media.",
                    },
                    status=410,
                )

        # Media can be viewed
        view_url = f"/media/view/{media.id}/"
        filename = os.path.basename(media.file.name)
        is_image = filename.lower().endswith((".jpg", ".jpeg", ".png", ".gif", ".webp"))

        return JsonResponse(
            {
                "status": "ok",
                "view_url": view_url,
                "filename": filename,
                "is_image": is_image,
                "media_type": media.media_type,
                "can_view_multiple": media.media_type == "normal",
            }
        )

    except Exception as e:
        print(f"Error in get_media_for_view: {e}")
        return JsonResponse(
            {"status": "error", "message": "Media not found or error occurred."},
            status=404,
        )


@require_safe
def view_media(request, media_id):
    """Serve media file with appropriate viewing rules"""
    try:
        media = get_object_or_404(TemporaryMedia, id=media_id)

        # Check if media is expired (only for view-once)
        if (
            media.media_type == "once"
            and media.expires_at
            and timezone.now() > media.expires_at
        ):
            media.is_expired = True
            media.save()
            return HttpResponse("This media has expired.", status=410)

        # Get username
        username = (
            request.user.username if request.user.is_authenticated else "Anonymous"
        )

        # Check if already viewed (only for view-once)
        if media.media_type == "once":
            if request.user.is_authenticated:
                has_viewed = media.has_user_viewed(user=request.user)
            else:
                if not request.session.session_key:
                    request.session.create()
                has_viewed = media.has_user_viewed(
                    session_key=request.session.session_key
                )

            if has_viewed:
                return HttpResponse("You have already viewed this media.", status=410)

        # Mark as viewed for view-once media
        if media.media_type == "once":
            if request.user.is_authenticated:
                media.mark_as_viewed_by_user(user=request.user, username=username)
            else:
                media.mark_as_viewed_by_user(
                    session_key=request.session.session_key, username=username
                )

        # Serve the file
        content_type, _ = mimetypes.guess_type(media.file.name)
        if not content_type:
            content_type = "application/octet-stream"

        # Check if file exists
        if not media.file:
            return HttpResponse("Media file not found.", status=404)

        try:
            file_content = media.file.open("rb")
            response = FileResponse(file_content, content_type=content_type)
        except IOError:
            return HttpResponse("Error opening media file.", status=500)

        filename = os.path.basename(media.file.name)
        response["Content-Disposition"] = f'inline; filename="{filename}"'

        # Cache headers - normal media can be cached, view-once cannot
        if media.media_type == "normal":
            response["Cache-Control"] = "public, max-age=86400"  # 24 hours
        else:
            response["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response["Pragma"] = "no-cache"
            response["Expires"] = "0"

        return response

    except TemporaryMedia.DoesNotExist:
        return HttpResponse("Media not found.", status=404)
    except Exception as e:
        print(f"Error in view_media: {e}")
        return HttpResponse("Error loading media.", status=500)


# Add this function for permanent media URLs
@require_safe
def get_permanent_media_url(request, media_id):
    """Get a permanent URL for normal media"""
    try:
        media = get_object_or_404(TemporaryMedia, id=media_id, media_type="normal")

        if not media.file:
            return JsonResponse(
                {"status": "error", "message": "Media file not found"}, status=404
            )

        return JsonResponse(
            {
                "status": "ok",
                "url": media.file.url,
                "filename": os.path.basename(media.file.name),
                "is_image": media.file.name.lower().endswith(
                    (".jpg", ".jpeg", ".png", ".gif", ".webp")
                ),
            }
        )

    except TemporaryMedia.DoesNotExist:
        return JsonResponse(
            {"status": "error", "message": "Media not found"}, status=404
        )


@login_required
def profile_edit(request):
    profile = Profile.objects.get(user=request.user)

    if request.method == "POST":
        action = request.POST.get("action")

        if action == "edit_profile":
            username = request.POST.get("username", "").strip()
            description = request.POST.get("description", "").strip()

            if username and 3 <= len(username) <= 150:
                request.user.username = username
                request.user.save()

            if len(description) <= 500:
                profile.description = description
                profile.save()

            request.session["profile_saved"] = True
            return redirect("profile_edit")

        elif action == "change_avatar":
            new_avatar = request.POST.get("avatar", "")
            valid_avatars = ["avt1.jpg", "avt2.jpg", "avt3.jpg", "avt4.jpg", "avt5.jpg"]

            if new_avatar in valid_avatars:
                profile.avatar = new_avatar
                profile.save()
                request.session["avatar_saved"] = True
                return redirect("profile_edit")
            else:
                request.session["avatar_error"] = True
                return redirect("profile_edit")

        elif action == "change_password":
            current_password = request.POST.get("current_password")
            new_password = request.POST.get("new_password")
            confirm_password = request.POST.get("confirm_password")

            # Validate current password
            if not request.user.check_password(current_password):
                request.session["password_error"] = "Current password is incorrect"
                return redirect("profile_edit")

            # Validate new password matches confirmation
            if new_password != confirm_password:
                request.session["password_error"] = "New passwords do not match"
                return redirect("profile_edit")

            # Validate password length
            if len(new_password) < 6:
                request.session["password_error"] = (
                    "Password must be at least 6 characters"
                )
                return redirect("profile_edit")

            # Validate password contains letter and number
            if not any(char.isalpha() for char in new_password) or not any(
                char.isdigit() for char in new_password
            ):
                request.session["password_error"] = (
                    "Password must contain at least one letter and one number"
                )
                return redirect("profile_edit")

            # Check if new password is the same as current
            if current_password == new_password:
                request.session["password_error"] = (
                    "New password cannot be the same as current password"
                )
                return redirect("profile_edit")

            # Change the password
            request.user.set_password(new_password)
            request.user.save()

            # Update the session to prevent logout
            update_session_auth_hash(request, request.user)

            request.session["password_saved"] = True
            return redirect("profile_edit")

    profile_saved = request.session.pop("profile_saved", False)
    avatar_saved = request.session.pop("avatar_saved", False)
    avatar_error = request.session.pop("avatar_error", False)
    password_saved = request.session.pop("password_saved", False)
    password_error = request.session.pop("password_error", None)

    return render(
        request,
        "profile_edit.html",
        {
            "profile": profile,
            "user": request.user,
            "profile_saved": profile_saved,
            "avatar_saved": avatar_saved,
            "avatar_error": avatar_error,
            "password_saved": password_saved,
            "password_error": password_error,
        },
    )


@login_required
def profile_view(request):
    profile = Profile.objects.get(user=request.user)

    friends_count = Friendship.objects.filter(
        (
            Q(from_user=request.user, status="accepted")
            | Q(to_user=request.user, status="accepted")
        )
    ).count()

    thirty_days_ago = timezone.now() - timedelta(days=30)
    rooms_created = Room.objects.filter(created_at__gte=thirty_days_ago).count()

    days_active = (timezone.now().date() - request.user.date_joined.date()).days
    days_active = max(1, days_active)

    messages_sent = friends_count * 15 + rooms_created * 8
    messages_sent = max(0, messages_sent)

    return render(
        request,
        "profile.html",
        {
            "profile": profile,
            "user": request.user,
            "friends_count": friends_count,
            "rooms_created": rooms_created,
            "messages_sent": messages_sent,
            "days_active": days_active,
        },
    )


def login_view(request):
    if request.user.is_authenticated:
        return redirect("index")

    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)

            if request.POST.get("remember"):
                request.session.set_expiry(30 * 24 * 60 * 60)
            else:
                request.session.set_expiry(24 * 60 * 60)

            next_page = request.GET.get("next", "index")
            messages.success(request, f"Welcome back, {user.username}!")
            return redirect(next_page)
        else:
            messages.error(request, "Invalid username or password.")
    else:
        form = AuthenticationForm()

    context = {"login_form": form}
    if request.user.is_authenticated:
        context["pending_requests"] = Friendship.objects.filter(
            to_user=request.user, status="pending"
        ).count()
        context["unread_notifications"] = Notification.objects.filter(
            user=request.user, is_read=False
        ).count()

    return render(request, "login.html", context)


def register_view(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect("index")
    else:
        form = RegisterForm()
    return render(request, "register.html", {"register_form": form})


def logout_view(request):
    logout(request)
    return redirect("/")


# In views.py - Update friend_list function
# In views.py - Update friend_list function
@login_required
def friend_list(request):
    """Friend management page with chat buttons"""
    # Get accepted friendships
    accepted_friendships = Friendship.objects.filter(
        Q(from_user=request.user, status="accepted")
        | Q(to_user=request.user, status="accepted")
    ).select_related("from_user", "to_user")

    # Process friends with online status
    processed_friendships = []
    for friendship in accepted_friendships:
        if friendship.from_user == request.user:
            friend = friendship.to_user
        else:
            friend = friendship.from_user

        # Check if friend is online (active within last 5 minutes)
        is_online = False
        last_seen = None
        if friend.last_login:
            last_seen = friend.last_login
            if timezone.now() - friend.last_login < timedelta(minutes=5):
                is_online = True

        # Get friend's profile
        try:
            friend_profile = Profile.objects.get(user=friend)
        except Profile.DoesNotExist:
            friend_profile = Profile.objects.create(user=friend)

        processed_friendships.append(
            {
                "friendship": friendship,
                "friend": friend,
                "friend_profile": friend_profile,
                "is_online": is_online,
                "last_seen": last_seen,
            }
        )

    # Get pending requests with status
    pending_requests = []
    for req in Friendship.objects.filter(
        to_user=request.user, status="pending"
    ).select_related("from_user"):
        sender = req.from_user
        is_online = False
        if sender.last_login and (
            timezone.now() - sender.last_login < timedelta(minutes=5)
        ):
            is_online = True

        pending_requests.append(
            {
                "request": req,
                "sender": sender,
                "is_online": is_online,
                "last_seen": sender.last_login,
            }
        )

    # Get sent requests with status
    sent_requests = []
    for req in Friendship.objects.filter(
        from_user=request.user, status="pending"
    ).select_related("to_user"):
        receiver = req.to_user
        is_online = False
        if receiver.last_login and (
            timezone.now() - receiver.last_login < timedelta(minutes=5)
        ):
            is_online = True

        sent_requests.append(
            {
                "request": req,
                "receiver": receiver,
                "is_online": is_online,
                "last_seen": receiver.last_login,
            }
        )

    # Count unread notifications
    unread_notifications = Notification.objects.filter(
        user=request.user, is_read=False
    ).count()

    return render(
        request,
        "friend_list.html",
        {
            "accepted_friends": processed_friendships,
            "pending_requests": pending_requests,
            "sent_requests": sent_requests,
            "user": request.user,
            "unread_notifications": unread_notifications,
            "pending_requests_count": len(pending_requests),
        },
    )


@login_required
@require_POST
def send_friend_request(request):
    username = request.POST.get("username")

    if not username:
        return JsonResponse({"status": "error", "message": "Username required"})

    if username == request.user.username:
        return JsonResponse({"status": "error", "message": "Cannot add yourself"})

    try:
        to_user = User.objects.get(username=username)
    except User.DoesNotExist:
        return JsonResponse({"status": "error", "message": "User not found"})

    existing = Friendship.objects.filter(
        Q(from_user=request.user, to_user=to_user)
        | Q(from_user=to_user, to_user=request.user)
    ).first()

    if existing:
        if existing.status == "pending":
            if existing.from_user == request.user:
                return JsonResponse(
                    {"status": "error", "message": "Request already sent"}
                )
            else:
                return JsonResponse(
                    {
                        "status": "error",
                        "message": "This user already sent you a request",
                    }
                )
        elif existing.status == "accepted":
            return JsonResponse({"status": "error", "message": "Already friends"})
        elif existing.status == "blocked":
            return JsonResponse({"status": "error", "message": "Cannot send request"})

    friendship = Friendship.objects.create(
        from_user=request.user, to_user=to_user, status="pending"
    )

    Notification.objects.create(
        user=to_user,
        notification_type="friend_request",
        title="New Friend Request",
        message=f"{request.user.username} wants to be your friend!",
        related_id=str(friendship.id),
    )

    return JsonResponse({"status": "success", "message": "Friend request sent"})


@login_required
@require_POST
def respond_friend_request(request):
    request_id = request.POST.get("request_id")
    action = request.POST.get("action")

    try:
        friendship = Friendship.objects.get(
            id=request_id, to_user=request.user, status="pending"
        )
    except Friendship.DoesNotExist:
        return JsonResponse({"status": "error", "message": "Friend request not found"})

    if action == "accept":
        friendship.status = "accepted"
        friendship.save()

        Notification.objects.create(
            user=friendship.from_user,
            notification_type="friend_accepted",
            title="Friend Request Accepted",
            message=f"{request.user.username} accepted your friend request!",
            related_id=str(friendship.id),
        )

        return JsonResponse({"status": "success", "message": "Friend request accepted"})
    elif action == "reject":
        friendship.status = "blocked"
        friendship.save()
        return JsonResponse({"status": "success", "message": "Friend request rejected"})

    return JsonResponse({"status": "error", "message": "Invalid action"})


@login_required
def notifications_view(request):
    notifications = Notification.objects.filter(user=request.user).order_by(
        "-created_at"
    )
    unread_count = notifications.filter(is_read=False).count()

    return render(
        request,
        "notifications.html",
        {
            "notifications": notifications,
            "unread_count": unread_count,
        },
    )


@login_required
@require_POST
def mark_notification_read(request):
    notification_id = request.POST.get("notification_id")

    try:
        notification = Notification.objects.get(id=notification_id, user=request.user)
        notification.is_read = True
        notification.save()
        return JsonResponse({"status": "success"})
    except Notification.DoesNotExist:
        return JsonResponse({"status": "error", "message": "Notification not found"})


@login_required
def create_complaint(request):
    if request.method == "POST":
        subject = request.POST.get("subject")
        message = request.POST.get("message")
        email = request.POST.get("email", "")

        if not subject or not message:
            return render(
                request,
                "create_complaint.html",
                {"error": "Subject and message are required"},
            )

        complaint = Complaint.objects.create(
            user=request.user,
            username=request.user.username,
            email=email if email else None,
            subject=subject,
            message=message,
            status="pending",
        )

        admins = User.objects.filter(is_staff=True)
        for admin in admins:
            Notification.objects.create(
                user=admin,
                notification_type="complaint",
                title="New Complaint/Bug Report",
                message=f"New complaint: {subject}",
                related_id=str(complaint.id),
            )

        return redirect("view_complaints")

    return render(request, "create_complaint.html")


@login_required
def view_complaints(request):
    if request.user.is_staff:
        complaints = Complaint.objects.all().order_by("-created_at")
    else:
        complaints = Complaint.objects.filter(
            Q(user=request.user) | Q(username=request.user.username)
        ).order_by("-created_at")

    return render(
        request,
        "view_complaints.html",
        {
            "complaints": complaints,
            "is_admin": request.user.is_staff,
        },
    )


@login_required
def get_random_room(request):
    active_rooms = Room.objects.filter(is_closed=False, is_private=False)

    if active_rooms.exists():
        random_room = random.choice(list(active_rooms))
        return JsonResponse(
            {
                "status": "success",
                "room_id": str(random_room.id),
                "short_code": random_room.short_code,
                "room_name": random_room.name,
            }
        )
    else:
        return JsonResponse({"status": "error", "message": "No active rooms available"})


@login_required
@require_POST
@csrf_exempt
def create_dm_room(request):
    """Create a direct message room between two friends"""
    try:
        data = json.loads(request.body)
        friend_id = data.get("friend_id")

        if not friend_id:
            return JsonResponse({"success": False, "error": "Friend ID required"})

        friend = User.objects.get(id=friend_id)

        # Check if they are friends
        friendship = Friendship.objects.filter(
            Q(from_user=request.user, to_user=friend, status="accepted")
            | Q(from_user=friend, to_user=request.user, status="accepted")
        ).first()

        if not friendship:
            return JsonResponse(
                {
                    "success": False,
                    "error": "You need to be friends to start a direct message.",
                }
            )

        # Check if DM room already exists
        existing_dm = get_dm_room(request.user, friend)
        if existing_dm:
            # Ensure both users are in dm_participants
            existing_dm.dm_participants.add(request.user, friend)
            existing_dm.save()

            return JsonResponse(
                {
                    "success": True,
                    "room_id": str(existing_dm.id),
                    "short_code": existing_dm.short_code or "",
                    "room_name": existing_dm.name,
                    "redirect_url": f"/chat/{existing_dm.short_code or existing_dm.id}/",
                    "already_exists": True,
                }
            )

        # Generate unique room ID for this DM pair
        user_ids = sorted([str(request.user.id), str(friend.id)])
        room_name = f"DM: {request.user.username} & {friend.username}"

        # Create a hash from user IDs for consistent room ID
        import hashlib
        from uuid import UUID

        room_hash = hashlib.md5(f"dm_{user_ids[0]}_{user_ids[1]}".encode()).hexdigest()

        # Use first 32 chars of hash as UUID
        room_uuid = UUID(room_hash[:32])

        # Create the DM room with proper settings
        room = Room.objects.create(
            id=room_uuid,
            name=room_name,
            room_type="direct",
            is_private=True,
            password=None,
            created_by=request.user,
        )
        UserRoomJoin.objects.update_or_create(
            user=request.user, room=room, defaults={"joined_at": timezone.now()}
        )

        UserRoomJoin.objects.update_or_create(
            user=friend, room=room, defaults={"joined_at": timezone.now()}
        )
        # CRITICAL: Add participants BEFORE saving UserRoomAccess
        room.dm_participants.add(request.user, friend)
        room.save()  # Make sure to save after adding participants

        # Create UserRoomAccess entries (without password)
        UserRoomAccess.objects.get_or_create(
            user=request.user,
            room=room,
            defaults={
                "password_hash": "dm_no_password_required",
                "expires_at": timezone.now() + timedelta(days=365),
            },
        )

        UserRoomAccess.objects.get_or_create(
            user=friend,
            room=room,
            defaults={
                "password_hash": "dm_no_password_required",
                "expires_at": timezone.now() + timedelta(days=365),
            },
        )

        # Double-check participants were added
        room.refresh_from_db()
        participant_count = room.dm_participants.count()

        return JsonResponse(
            {
                "success": True,
                "room_id": str(room.id),
                "short_code": room.short_code or "",
                "room_name": room.name,
                "redirect_url": f"/chat/{room.short_code or room.id}/",
                "already_exists": False,
                "participants_added": participant_count,
            }
        )

    except User.DoesNotExist:
        return JsonResponse({"success": False, "error": "Friend not found."})
    except json.JSONDecodeError:
        return JsonResponse({"success": False, "error": "Invalid JSON data."})
    except Exception as e:
        import traceback

        error_details = traceback.format_exc()
        print(f"Error creating DM room: {e}")
        print(f"Error details: {error_details}")
        return JsonResponse(
            {"success": False, "error": str(e), "details": error_details}
        )


def get_dm_room(user1, user2):
    """Get existing DM room between two users"""
    user_ids = sorted([str(user1.id), str(user2.id)])
    room_hash = hashlib.md5(f"dm_{user_ids[0]}_{user_ids[1]}".encode()).hexdigest()

    try:
        from uuid import UUID

        room_uuid = UUID(room_hash[:32])
        return Room.objects.get(id=room_uuid, room_type="direct")
    except (ValueError, Room.DoesNotExist):
        return None


@login_required
def my_dm_rooms(request):
    """Show only DM rooms the user is a participant in"""
    # Get DM rooms where user is a participant
    dm_rooms = Room.objects.filter(
        room_type="direct", dm_participants=request.user, is_closed=False
    ).order_by("-created_at")

    # Get info about each DM room
    dm_rooms_info = []
    for room in dm_rooms:
        # Get the other participant
        other_participants = room.dm_participants.exclude(id=request.user.id)
        if other_participants.exists():
            friend = other_participants.first()

            try:
                friend_profile = Profile.objects.get(user=friend)
            except Profile.DoesNotExist:
                friend_profile = Profile.objects.create(user=friend)

            # Get last message from Redis
            try:
                r = redis.Redis(
                    host="localhost", port=6379, db=0, decode_responses=True
                )
                messages_key = f"messages_{room.id}"
                last_msg_json = r.lindex(messages_key, 0)

                last_message = None
                last_message_time = None

                if last_msg_json:
                    last_msg = json.loads(last_msg_json)
                    message_text = last_msg.get("message", "")
                    last_message = (
                        message_text[:50] + "..."
                        if len(message_text) > 50
                        else message_text
                    )
                    last_message_time = last_msg.get("timestamp")

                    # Convert timestamp to readable format
                    if last_message_time:
                        import time
                        from datetime import datetime

                        dt = datetime.fromtimestamp(last_message_time)
                        last_message_time = dt.strftime("%I:%M %p")
            except Exception as e:
                print(f"Error fetching Redis messages: {e}")
                last_message = None
                last_message_time = None

            # Check if friend is online
            is_online = False
            if friend.last_login:
                if timezone.now() - friend.last_login < timedelta(minutes=5):
                    is_online = True

            dm_rooms_info.append(
                {
                    "room": room,
                    "friend": friend,
                    "friend_profile": friend_profile,
                    "friend_name": friend.username,  # Add this line
                    "last_message": last_message,
                    "last_message_time": last_message_time,
                    "is_online": is_online,
                }
            )

    return render(
        request,
        "my_dm_rooms.html",
        {
            "dm_rooms": dm_rooms_info,
            "unread_notifications": Notification.objects.filter(
                user=request.user, is_read=False
            ).count(),
            "pending_requests": Friendship.objects.filter(
                to_user=request.user, status="pending"
            ).count(),
        },
    )


@login_required
@require_POST
def create_dm_chat(request, friend_id):
    try:
        friend = User.objects.get(id=friend_id)

        friendship = Friendship.objects.filter(
            Q(from_user=request.user, to_user=friend, status="accepted")
            | Q(from_user=friend, to_user=request.user, status="accepted")
        ).first()

        if not friendship:
            return JsonResponse(
                {"status": "error", "message": "You are not friends with this user"}
            )

        room_name = f"DM: {request.user.username} & {friend.username}"

        user_ids = sorted([str(request.user.id), str(friend.id)])
        room_hash = hashlib.md5(f"{user_ids[0]}_{user_ids[1]}".encode()).hexdigest()
        room_uuid = uuid.UUID(room_hash[:32])

        room, created = Room.objects.get_or_create(
            id=room_uuid,
            defaults={"name": room_name, "is_private": True, "room_type": "direct"},
        )

        return JsonResponse(
            {
                "status": "success",
                "room_id": str(room.id),
                "room_name": room.name,
                "created": created,
            }
        )

    except User.DoesNotExist:
        return JsonResponse({"status": "error", "message": "Friend not found"})


# Add this to views.py for debugging
@login_required
def check_dm_status(request, room_id):
    """Check DM room status for debugging"""
    try:
        room = Room.objects.get(id=room_id)

        data = {
            "room_id": str(room.id),
            "room_name": room.name,
            "room_type": room.room_type,
            "is_direct": room.room_type == "direct",
            "current_user": request.user.username,
            "current_user_id": str(request.user.id),
        }

        # Check dm_participants
        participants = room.dm_participants.all()
        data["dm_participants"] = [
            {"id": str(p.id), "username": p.username} for p in participants
        ]

        data["is_participant"] = room.dm_participants.filter(
            id=request.user.id
        ).exists()

        # Check UserRoomAccess
        user_access = UserRoomAccess.objects.filter(
            user=request.user, room=room
        ).first()
        data["has_user_access"] = bool(user_access)
        if user_access:
            data["user_access_valid"] = user_access.is_valid()

        return JsonResponse(data)

    except Room.DoesNotExist:
        return JsonResponse({"error": "Room not found"})


@login_required
@require_POST
def remove_friend(request):
    friend_id = request.POST.get("friend_id")

    try:
        friend = User.objects.get(id=friend_id)

        friendship = Friendship.objects.filter(
            Q(from_user=request.user, to_user=friend, status="accepted")
            | Q(from_user=friend, to_user=request.user, status="accepted")
        ).first()

        if friendship:
            friendship.delete()
            return JsonResponse({"status": "success", "message": "Friend removed"})
        else:
            return JsonResponse({"status": "error", "message": "Friendship not found"})

    except User.DoesNotExist:
        return JsonResponse({"status": "error", "message": "User not found"})


@login_required
@require_POST
def cancel_friend_request(request):
    request_id = request.POST.get("request_id")

    try:
        friendship = Friendship.objects.get(
            id=request_id, from_user=request.user, status="pending"
        )
        friendship.delete()
        return JsonResponse(
            {"status": "success", "message": "Friend request cancelled"}
        )

    except Friendship.DoesNotExist:
        return JsonResponse({"status": "error", "message": "Request not found"})


@login_required
def user_stats_api(request):
    user = request.user

    days_active = (datetime.now().date() - user.date_joined.date()).days
    days_active = max(1, days_active)

    friends_count = Friendship.objects.filter(
        (Q(from_user=user, status="accepted") | Q(to_user=user, status="accepted"))
    ).count()

    thirty_days_ago = timezone.now() - timedelta(days=30)
    rooms_created = Room.objects.filter(created_at__gte=thirty_days_ago).count()

    messages_sent = friends_count * 10 + rooms_created * 5
    messages_sent = max(0, messages_sent)

    return JsonResponse(
        {
            "status": "success",
            "stats": {
                "friends_count": friends_count,
                "rooms_created": rooms_created,
                "messages_sent": messages_sent,
                "days_active": days_active,
                "member_since": user.date_joined.strftime("%B %d, %Y"),
                "avatar": (
                    user.profile.avatar if hasattr(user, "profile") else "avt1.jpg"
                ),
            },
        }
    )


@csrf_exempt
@require_POST
def store_room_access(request):
    """Store room access in session for password-less entry (AJAX endpoint)"""
    try:
        data = json.loads(request.body)
        room_id = data.get("room_id")
        access_token = data.get("access_token")

        if not room_id:
            return JsonResponse({"success": False, "error": "Room ID required"})

        try:
            room = Room.objects.get(id=room_id, is_closed=False)
        except Room.DoesNotExist:
            return JsonResponse({"success": False, "error": "Room not found"})

        # For logged-in users, store in database
        if request.user.is_authenticated:
            # Check if access is already stored
            user_access = UserRoomAccess.objects.filter(
                user=request.user, room=room
            ).first()

            if not user_access and room.password:
                # Store access for future
                password_hash = hashlib.sha256(room.password.encode()).hexdigest()
                UserRoomAccess.objects.create(
                    user=request.user,
                    room=room,
                    password_hash=password_hash,
                    expires_at=timezone.now() + timedelta(days=30),
                )

        # Store in session for immediate access
        session_key = f"room_access_{room.id}"
        request.session[session_key] = {
            "accessed_at": timezone.now().isoformat(),
            "room_name": room.name,
            "stored": True,
        }

        # Also store in private_rooms for backward compatibility
        if "private_rooms" not in request.session:
            request.session["private_rooms"] = {}
        request.session["private_rooms"][str(room.id)] = room.password
        request.session.modified = True

        return JsonResponse(
            {
                "success": True,
                "message": "Room access stored successfully",
                "room_id": str(room.id),
                "room_name": room.name,
            }
        )

    except json.JSONDecodeError:
        return JsonResponse({"success": False, "error": "Invalid JSON data"})
    except Exception as e:
        print(f"Error storing room access: {e}")
        return JsonResponse({"success": False, "error": str(e)})


@csrf_exempt
@require_POST
def verify_room_password(request, room_id):
    """AJAX endpoint to verify room password and save access - accepts both UUID and short codes"""
    try:
        # Try to find room by UUID first
        try:
            room_uuid = uuid.UUID(room_id)
            room = Room.objects.get(id=room_uuid, is_closed=False)
        except (ValueError, Room.DoesNotExist):
            # If not a valid UUID, try as short code
            try:
                room = Room.objects.get(short_code=room_id.upper(), is_closed=False)
            except Room.DoesNotExist:
                return JsonResponse({"success": False, "error": "Room not found"})

        password = request.POST.get("password", "").strip()

        if not room.password:
            # Room doesn't have a password (shouldn't happen for private rooms)
            return JsonResponse(
                {"success": False, "error": "This room doesn't require a password"}
            )

        if password == room.password:
            # Save access based on user type
            save_room_access(request, room)

            # Check "remember" checkbox if present
            remember = request.POST.get("remember") == "true"
            if remember and request.user.is_authenticated:
                # Extend expiry for remembered rooms
                user_access = UserRoomAccess.objects.filter(
                    user=request.user, room=room
                ).first()
                if user_access:
                    user_access.expires_at = timezone.now() + timedelta(days=90)
                    user_access.save()

            # Use short code for URL if available, otherwise use UUID
            if room.short_code:
                redirect_url = f"/chat/{room.short_code}/"
            else:
                redirect_url = f"/chat/{room.id}/"

            response_data = {
                "success": True,
                "redirect_url": redirect_url,
                "message": "Access granted! Redirecting...",
                "room_id": str(room.id),
                "short_code": room.short_code or "",
            }

            return JsonResponse(response_data)

        return JsonResponse({"success": False, "error": "Incorrect password"})

    except Exception as e:
        print(f"Error in verify_room_password: {e}")
        return JsonResponse({"success": False, "error": f"Error: {str(e)}"})


@login_required
def my_private_rooms(request):
    """Show all private rooms the user has access to"""
    # Get user's room accesses
    user_accesses = (
        UserRoomAccess.objects.filter(user=request.user)
        .select_related("room")
        .order_by("-last_accessed")
    )

    # Get accessible rooms
    accessible_rooms = []
    for access in user_accesses:
        if not access.room.is_closed:
            accessible_rooms.append(access.room)

    return render(
        request,
        "my_private_rooms.html",
        {
            "accessible_rooms": accessible_rooms,
            "user_accesses": user_accesses,
        },
    )


@login_required
@require_POST
def forget_room_access(request, room_id):
    """Forget saved access to a private room"""
    try:
        room = Room.objects.get(id=room_id)

        # Remove from UserRoomAccess
        UserRoomAccess.objects.filter(user=request.user, room=room).delete()

        # Remove from session
        private_rooms = request.session.get("private_rooms", {})
        if str(room.id) in private_rooms:
            del private_rooms[str(room.id)]
            request.session["private_rooms"] = private_rooms
            request.session.modified = True

        return JsonResponse({"success": True, "message": "Room access forgotten"})

    except Room.DoesNotExist:
        return JsonResponse({"success": False, "error": "Room not found"})


@login_required
@csrf_exempt
def get_sidebar_content(request):
    """API endpoint to get sidebar content (AJAX fallback)"""
    try:
        user = request.user

        # Get active rooms (non-DM)
        my_active_rooms = []
        try:
            yesterday = timezone.now() - timedelta(hours=24)
            recent_room_ids = (
                RoomAccess.objects.filter(user=user, last_activity__gte=yesterday)
                .values_list("room_id", flat=True)
                .distinct()[:5]
            )

            if recent_room_ids:
                rooms = Room.objects.filter(
                    id__in=recent_room_ids, is_closed=False
                ).exclude(room_type="direct")[:5]

                for room in rooms:
                    my_active_rooms.append(
                        {
                            "id": str(room.id),
                            "name": room.name,
                            "short_code": room.short_code,
                            "is_private": room.is_private,
                            "room_type": room.room_type,
                        }
                    )
        except:
            pass

        # Get recent DMs
        my_recent_dms = []
        try:
            dm_rooms = Room.objects.filter(
                room_type="direct", dm_participants=user, is_closed=False
            ).order_by("-created_at")[:3]

            for room in dm_rooms:
                other_participants = room.dm_participants.exclude(id=user.id)
                if other_participants.exists():
                    friend = other_participants.first()

                    is_online = False
                    if friend.last_login:
                        if timezone.now() - friend.last_login < timedelta(minutes=5):
                            is_online = True

                    my_recent_dms.append(
                        {
                            "room_id": str(room.id),
                            "friend_name": friend.username,
                            "is_online": is_online,
                            "last_message_time": None,  # Can be implemented
                        }
                    )
        except:
            pass

        return JsonResponse(
            {
                "success": True,
                "rooms": my_active_rooms,
                "dms": my_recent_dms,
            }
        )

    except Exception as e:
        return JsonResponse(
            {
                "success": False,
                "error": str(e),
                "rooms": [],
                "dms": [],
            }
        )


# In views.py - Update public_profile_view function
@login_required
def public_profile_view(request, username):
    """View another user's profile with appropriate action buttons"""
    target_user = get_object_or_404(User, username=username)

    # If user is viewing their own profile, redirect to the private profile view
    if target_user == request.user:
        return redirect("profile")

    try:
        profile = Profile.objects.get(user=target_user)
    except Profile.DoesNotExist:
        profile = Profile.objects.create(user=target_user)

    # Check if user is online (active within last 5 minutes)
    is_online = False
    last_seen = None
    if target_user.last_login:
        last_seen = target_user.last_login
        if timezone.now() - target_user.last_login < timedelta(minutes=5):
            is_online = True

    # Determine friendship status
    friendship = Friendship.objects.filter(
        Q(from_user=request.user, to_user=target_user)
        | Q(from_user=target_user, to_user=request.user)
    ).first()

    status = "none"
    request_id = None

    if friendship:
        request_id = friendship.id
        if friendship.status == "accepted":
            status = "friends"
        elif friendship.status == "pending":
            if friendship.from_user == request.user:
                status = "request_sent"
            else:
                status = "request_received"
        elif friendship.status == "blocked":
            status = "blocked"

    # Get stats for the target user (same logic as private profile)
    friends_count = Friendship.objects.filter(
        (
            Q(from_user=target_user, status="accepted")
            | Q(to_user=target_user, status="accepted")
        )
    ).count()

    thirty_days_ago = timezone.now() - timedelta(days=30)
    rooms_created = Room.objects.filter(
        created_by=target_user, created_at__gte=thirty_days_ago
    ).count()

    days_active = (timezone.now().date() - target_user.date_joined.date()).days
    days_active = max(1, days_active)

    messages_sent = friends_count * 15 + rooms_created * 8
    messages_sent = max(0, messages_sent)

    return render(
        request,
        "public_profile.html",
        {
            "target_user": target_user,
            "profile": profile,
            "status": status,
            "request_id": request_id,
            "friends_count": friends_count,
            "rooms_created": rooms_created,
            "messages_sent": messages_sent,
            "days_active": days_active,
            "is_online": is_online,
            "last_seen": last_seen,
        },
    )


# In views.py - Add this endpoint
@login_required
@require_safe
def check_online_status(request):
    """API endpoint to check which friends are online"""
    from datetime import datetime, timedelta
    from django.utils import timezone

    # Get all accepted friends
    accepted_friendships = Friendship.objects.filter(
        Q(from_user=request.user, status="accepted")
        | Q(to_user=request.user, status="accepted")
    )

    # Check who is online (active within last 5 minutes)
    online_users = []
    five_minutes_ago = timezone.now() - timedelta(minutes=5)

    for friendship in accepted_friendships:
        if friendship.from_user == request.user:
            friend = friendship.to_user
        else:
            friend = friendship.from_user

        if friend.last_login and friend.last_login >= five_minutes_ago:
            online_users.append(str(friend.id))

    return JsonResponse(
        {
            "success": True,
            "online_users": online_users,
            "timestamp": timezone.now().isoformat(),
        }
    )


# chat/views.py - Add this cleanup view
@login_required
def cleanup_expired_media(request):
    """Admin view to manually clean up expired media"""
    if not request.user.is_staff:
        return HttpResponse("Access denied", status=403)

    expired_count = 0
    from datetime import timedelta

    # Find media that expired more than 24 hours ago
    cutoff_time = timezone.now() - timedelta(hours=24)

    expired_media = TemporaryMedia.objects.filter(
        media_type="once", expires_at__lt=cutoff_time
    )

    expired_count = expired_media.count()

    for media in expired_media:
        if media.file:
            try:
                media.file.delete(save=False)
            except:
                pass
        media.delete()

    return JsonResponse(
        {
            "success": True,
            "message": f"Cleaned up {expired_count} expired media files",
            "count": expired_count,
        }
    )


# In chat/views.py - Add this function for backward compatibility
@csrf_exempt
@require_POST
def upload_once_view_media(request):
    """Legacy endpoint for view-once media uploads (for backward compatibility)"""
    if not request.session.session_key:
        request.session.create()

    file = request.FILES.get("file")
    room_id = request.POST.get("room_id")

    if not file or not room_id:
        return JsonResponse({"error": "Missing file or room"}, status=400)

    try:
        room = Room.objects.get(id=room_id)
        if room.is_closed:
            return JsonResponse({"error": "Room is closed"}, status=410)
    except Room.DoesNotExist:
        return JsonResponse({"error": "Room not found"}, status=404)

    MAX_SIZE = 10 * 1024 * 1024
    if file.size > MAX_SIZE:
        return JsonResponse({"error": "File too large (max 10MB)"}, status=400)

    ext = os.path.splitext(file.name)[1].lower()
    allowed_extensions = [".jpg", ".jpeg", ".png", ".gif", ".mp4", ".mov"]
    if ext not in allowed_extensions:
        return JsonResponse({"error": "File type not allowed"}, status=400)

    username = request.user.username if request.user.is_authenticated else "Anonymous"

    expires_at = timezone.now() + timedelta(hours=24)

    media = TemporaryMedia.objects.create(
        file=file,
        uploader_username=username,
        room_id=room.id,
        media_type="once",  # Force view-once for legacy endpoint
        expires_at=expires_at,
    )

    return JsonResponse(
        {
            "status": "ok",
            "media_id": str(media.id),
            "filename": file.name,
            "is_image": ext in [".jpg", ".jpeg", ".png", ".gif"],
            "media_type": "once",
            "expires_at": expires_at.isoformat(),
        }
    )


@require_safe
def view_once_media(request, media_id):
    """Legacy endpoint for view-once media (for backward compatibility)"""
    try:
        media = get_object_or_404(TemporaryMedia, id=media_id)

        # Check if media is expired
        if media.expires_at and timezone.now() > media.expires_at:
            return HttpResponse("This media has expired.", status=410)

        # Get username
        username = (
            request.user.username if request.user.is_authenticated else "Anonymous"
        )

        # Check if already viewed
        if request.user.is_authenticated:
            has_viewed = media.has_user_viewed(user=request.user)
        else:
            if not request.session.session_key:
                request.session.create()
            has_viewed = media.has_user_viewed(session_key=request.session.session_key)

        if has_viewed:
            return HttpResponse("You have already viewed this media.", status=410)

        # Mark as viewed
        if request.user.is_authenticated:
            media.mark_as_viewed_by_user(user=request.user, username=username)
        else:
            media.mark_as_viewed_by_user(
                session_key=request.session.session_key, username=username
            )

        # Serve the file
        content_type, _ = mimetypes.guess_type(media.file.name)
        if not content_type:
            content_type = "application/octet-stream"

        # Check if file exists
        if not media.file:
            return HttpResponse("Media file not found.", status=404)

        try:
            file_content = media.file.open("rb")
            response = FileResponse(file_content, content_type=content_type)
        except IOError:
            return HttpResponse("Error opening media file.", status=500)

        filename = os.path.basename(media.file.name)
        response["Content-Disposition"] = f'inline; filename="{filename}"'
        response["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response["Pragma"] = "no-cache"
        response["Expires"] = "0"

        return response

    except TemporaryMedia.DoesNotExist:
        return HttpResponse("Media not found.", status=404)
    except Exception as e:
        print(f"Error in view_once_media: {e}")
        return HttpResponse("Error loading media.", status=500)
