# chat/consumers.py
import json
import time
import redis
import uuid  
from datetime import datetime
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.utils import timezone
from django.core.exceptions import ObjectDoesNotExist
from .models import (
    Room,
    ChatMessage,
    TemporaryMedia,
    UserRoomAccess,
    MediaView,
    RoomAccess,
)

# Redis connection (reuse across consumers)
r = redis.Redis(host="localhost", port=6379, db=0, decode_responses=True)


class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_id = str(self.scope["url_route"]["kwargs"]["room_id"])
        self.room_group_name = f"chat_{self.room_id}"

        # Get user information
        user = self.scope.get("user")
        self.username = user.username if user and user.is_authenticated else "Anonymous"
        self.user = user

        # Get session for anonymous users
        self.session = self.scope.get("session", {})

        # For anonymous users, generate a consistent username
        if not user or not user.is_authenticated:
            session_key = (
                self.session.session_key
                if hasattr(self.session, "session_key")
                else None
            )
            if session_key:
                self.username = f"Anonymous_{session_key[:8]}"
            else:
                self.username = f"Anonymous_{int(time.time())}"

        room = await self.get_room()
        if not room or room.is_closed:
            await self.close()
            return

        # ---------- DM ACCESS ----------
        if room.room_type == "direct":
            if not user or not user.is_authenticated:
                await self.close()
                return
            if not await self.check_dm_participant(room, user):
                await self.close()
                return

        # ---------- CONNECTION TRACKING ----------
        connection_key = f"connections_{self.room_id}"
        client_id = self.channel_name
        is_new = not r.sismember(connection_key, client_id)

        if is_new:
            r.sadd(connection_key, client_id)
            r.expire(connection_key, 7 * 24 * 60 * 60)  # 7 days
            await self.channel_layer.group_add(self.room_group_name, self.channel_name)
            await self.accept()

        # ---------- MESSAGE LIST TTL ----------
        msg_key = f"messages_{self.room_id}"
        r.expire(msg_key, 7 * 24 * 60 * 60)  # 7 days

        # ---------- SEND FULL HISTORY ----------
        history = await self.get_message_history()
        await self.send(text_data=json.dumps({"type": "history", "messages": history}))

        # ---------- JOIN NOTIFICATION ----------
        if is_new:
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    "type": "chat_notification",
                    "username": self.username,
                    "message": f"{self.username} joined the room",
                },
            )

    # ------------------------------------------------------------------ #
    # DB helpers
    # ------------------------------------------------------------------ #
    @database_sync_to_async
    def get_room(self):
        try:
            return Room.objects.get(id=self.room_id)
        except Room.DoesNotExist:
            return None

    @database_sync_to_async
    def check_dm_participant(self, room, user):
        return room.dm_participants.filter(id=user.id).exists()

    @database_sync_to_async
    def save_message_to_db(
        self,
        msg_id,
        username,
        text,
        is_media=False,
        media_id=None,
        filename=None,
        is_image=False,
    ):
        return ChatMessage.objects.create(
            message_id=msg_id,
            room_id=self.room_id,
            username=username,
            original_message=text,
            edited_message=text,
            is_media=is_media,
            media_id=media_id,
            filename=filename,
            is_image=is_image,
        )

    @database_sync_to_async
    def update_message_db(self, msg_id, **kwargs):
        try:
            msg = ChatMessage.objects.get(message_id=msg_id, room_id=self.room_id)
            for k, v in kwargs.items():
                setattr(msg, k, v)
            msg.save()
        except ChatMessage.DoesNotExist:
            pass

    @database_sync_to_async
    def get_db_messages(self, limit=500):
        """Return newest `limit` messages ordered by created_at."""
        messages = list(
            ChatMessage.objects.filter(room_id=self.room_id)
            .order_by("-created_at")[:limit]
            .values(
                "message_id",
                "username",
                "original_message",
                "edited_message",
                "created_at",
                "is_edited",
                "is_deleted",
                "is_media",
                "media_id",
                "filename",
                "is_image",
                "media_type",  # Add this field
            )
        )
        return messages

    # ------------------------------------------------------------------ #
    # Message handling
    # ------------------------------------------------------------------ #
    async def receive(self, text_data):
        data = json.loads(text_data)
        msg_type = data.get("type")

        # ------------------ NEW MESSAGE ------------------
        if msg_type == "message":
            message = data.get("message", "")

            # Always use the stored username from connect
            username = self.username

            # Check if message is not empty
            if not message or not message.strip():
                return

            msg_id = f"{self.room_id}_{int(time.time()*1000)}"

            # Check if it's a media message
            is_media = data.get("is_media", False)
            media_id = data.get("media_id", "")
            filename = data.get("filename", "")
            is_image = data.get("is_image", False)

            # Save to DB only for authenticated users
            if self.user and self.user.is_authenticated:
                await self.save_message_to_db(
                    msg_id,
                    username,
                    message,
                    is_media=is_media,
                    media_id=media_id,
                    filename=filename,
                    is_image=is_image,
                )

            # Save to Redis (fast broadcast) for all users
            msg_payload = {
                "id": msg_id,
                "username": username,
                "message": message,
                "timestamp": time.time(),
                "reactions": {},
                "is_media": is_media,
                "media_id": media_id,
                "filename": filename,
                "is_image": is_image,
                "is_edited": False,
                "is_deleted": False,
            }
            await self.save_message_redis(msg_payload)

            # Broadcast
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    "type": "chat_message",
                    "id": msg_id,
                    "username": username,
                    "message": message,
                    "is_media": is_media,
                    "media_id": media_id,
                    "filename": filename,
                    "is_image": is_image,
                },
            )

        # ------------------ EDIT MESSAGE ------------------
        elif msg_type == "edit_message":
            msg_id = data.get("msg_id")
            new_text = data.get("message")
            username = data.get("username", "Anonymous")

            # Only allow editing for authenticated users
            if self.user and self.user.is_authenticated:
                # Update in database
                await self.update_message_db(
                    msg_id,
                    edited_message=new_text,
                    is_edited=True,
                    updated_at=timezone.now(),
                )

                # Update in Redis
                await self.update_redis_message(
                    msg_id, {"message": new_text, "is_edited": True}
                )

                # Broadcast edit
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        "type": "message_edited",
                        "msg_id": msg_id,
                        "message": new_text,
                        "username": username,
                    },
                )

        # ------------------ DELETE MESSAGE ------------------
        elif msg_type == "delete_message":
            msg_id = data.get("msg_id")
            username = data.get("username", "Anonymous")

            # Only allow deleting for authenticated users
            if self.user and self.user.is_authenticated:
                # Update in database
                await self.update_message_db(
                    msg_id,
                    is_deleted=True,
                    edited_message="[This message was deleted]",
                    deleted_at=timezone.now(),
                    deleted_by=username,
                )

                # Update in Redis
                await self.update_redis_message(
                    msg_id,
                    {"message": "[This message was deleted]", "is_deleted": True},
                )

                # Broadcast deletion
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        "type": "message_deleted",
                        "msg_id": msg_id,
                    },
                )

        # ------------------ UNSEND MESSAGE ------------------
        elif msg_type == "unsend_message":
            msg_id = data.get("msg_id")
            username = data.get("username", "Anonymous")

            # Only allow unsending for authenticated users
            if self.user and self.user.is_authenticated:
                # Delete from database
                await self.delete_message_db(msg_id)

                # Delete from Redis
                await self.delete_redis_message(msg_id)

                # Broadcast unsend
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        "type": "message_unsent",
                        "msg_id": msg_id,
                    },
                )

        # ------------------ REACTION ------------------
        elif msg_type == "reaction":
            msg_id = data.get("msg_id")
            emoji = data.get("emoji")

            # Add reaction in Redis
            await self.add_reaction_redis(msg_id, emoji)

            # Get updated reactions
            reactions = await self.get_reactions_redis(msg_id)

            # Broadcast reaction
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    "type": "reaction_update",
                    "msg_id": msg_id,
                    "reactions": reactions,
                },
            )

        # ------------------ TYPING ------------------
        elif msg_type == "typing":
            username = data.get("username")
            await self.channel_layer.group_send(
                self.room_group_name,
                {"type": "typing_indicator", "username": username},
            )

        # ------------------ VIEW-ONCE MEDIA ------------------
        elif msg_type == "view_once_media":
            media_id = data.get("media_id")
            await self.mark_view_once_media(media_id)

        # ------------------ CLOSE ROOM ------------------
        elif msg_type == "close_room":
            await self.handle_close_room()

    # ------------------------------------------------------------------ #
    # Redis helpers
    # ------------------------------------------------------------------ #
    async def save_message_redis(self, msg):
        key = f"messages_{self.room_id}"
        r.lpush(key, json.dumps(msg))
        r.ltrim(key, 0, 999)  # keep last 1000
        r.expire(key, 7 * 24 * 60 * 60)

    async def delete_message_db(self, msg_id):
        try:
            ChatMessage.objects.filter(message_id=msg_id, room_id=self.room_id).delete()
        except:
            pass

    async def delete_redis_message(self, msg_id):
        key = f"messages_{self.room_id}"
        msgs = r.lrange(key, 0, -1)
        updated_msgs = []

        for raw in msgs:
            try:
                msg = json.loads(raw)
                if msg.get("id") != msg_id:
                    updated_msgs.append(raw)
            except:
                pass

        if len(updated_msgs) != len(msgs):
            r.delete(key)
            for m in reversed(updated_msgs):
                r.lpush(key, m)
            r.expire(key, 7 * 24 * 60 * 60)

    async def update_redis_message(self, msg_id, updates):
        """Update a message in Redis"""
        key = f"messages_{self.room_id}"
        msgs = r.lrange(key, 0, -1)
        updated = False

        for i, raw in enumerate(msgs):
            try:
                msg = json.loads(raw)
                if msg.get("id") == msg_id:
                    msg.update(updates)
                    msgs[i] = json.dumps(msg)
                    updated = True
                    break
            except:
                continue

        if updated:
            r.delete(key)
            for m in reversed(msgs):
                r.lpush(key, m)
            r.expire(key, 7 * 24 * 60 * 60)

    async def add_reaction_redis(self, msg_id, emoji):
        """Add a reaction to a message in Redis"""
        key = f"messages_{self.room_id}"
        msgs = r.lrange(key, 0, -1)
        updated = False

        for i, raw in enumerate(msgs):
            try:
                msg = json.loads(raw)
                if msg.get("id") == msg_id:
                    reactions = msg.get("reactions", {})
                    reactions[emoji] = reactions.get(emoji, 0) + 1
                    msg["reactions"] = reactions
                    msgs[i] = json.dumps(msg)
                    updated = True
                    break
            except:
                continue

        if updated:
            r.delete(key)
            for m in reversed(msgs):
                r.lpush(key, m)
            r.expire(key, 7 * 24 * 60 * 60)

    async def get_reactions_redis(self, msg_id):
        """Get reactions for a message from Redis"""
        key = f"messages_{self.room_id}"
        msgs = r.lrange(key, 0, -1)

        for raw in msgs:
            try:
                msg = json.loads(raw)
                if msg.get("id") == msg_id:
                    return msg.get("reactions", {})
            except:
                continue
        return {}

    # ------------------------------------------------------------------ #
    # Room closure handlers
    # ------------------------------------------------------------------ #
    async def handle_close_room(self):
        """Handle room closure request"""
        try:
            # Check if user can close the room
            can_close = await self.check_can_close_room()
            if not can_close:
                await self.send(
                    json.dumps(
                        {
                            "type": "error",
                            "message": "Only room creator can close the room",
                        }
                    )
                )
                return

            # Get room info before closing
            room_info = await self.get_room_info()

            # Delete all media files for this room
            media_deleted = await self.delete_room_media()

            # Clear Redis data for this room
            await self.clear_room_redis()

            # Mark room as closed in database
            await self.close_room_db()

            # Broadcast room closure to all connected users
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    "type": "room_closed",
                    "message": f"Room '{room_info['name']}' has been closed by {self.username}",
                    "redirect": True,
                },
            )

        except Exception as e:
            print(f"Error closing room: {e}")
            await self.send(
                json.dumps(
                    {"type": "error", "message": f"Failed to close room: {str(e)}"}
                )
            )

    @database_sync_to_async
    def check_can_close_room(self):
        """Check if user can close the room"""
        try:
            room = Room.objects.get(id=self.room_id)
            user = self.user

            if not user or not user.is_authenticated:
                return False

            # Room creator can close
            if room.created_by == user:
                return True

            # Admin users can close
            if user.is_staff:
                return True

            return False
        except Room.DoesNotExist:
            return False

    @database_sync_to_async
    def get_room_info(self):
        """Get room information"""
        try:
            room = Room.objects.get(id=self.room_id)
            return {
                "id": str(room.id),
                "name": room.name,
                "short_code": room.short_code,
                "created_by": (
                    room.created_by.username if room.created_by else "Unknown"
                ),
                "created_at": room.created_at,
            }
        except Room.DoesNotExist:
            return {"name": "Unknown Room"}

    @database_sync_to_async
    def delete_room_media(self):
        """Delete all media files for this room"""
        try:
            media_files = TemporaryMedia.objects.filter(room_id=self.room_id)
            count = media_files.count()

            for media in media_files:
                # Delete the file from storage
                if media.file:
                    media.file.delete(save=False)
                # Delete the database record
                media.delete()

            return count
        except Exception as e:
            print(f"Error deleting room media: {e}")
            return 0

    async def clear_room_redis(self):
        """Clear all Redis data for this room"""
        try:
            # Delete messages
            messages_key = f"messages_{self.room_id}"
            r.delete(messages_key)

            # Delete connections
            connections_key = f"connections_{self.room_id}"
            r.delete(connections_key)

            # Find and delete all reaction keys for this room
            all_keys = r.keys(f"user_reaction_{self.room_id}_*")
            if all_keys:
                r.delete(*all_keys)

            # Find and delete all rate limit keys for this room
            rate_keys = r.keys(f"rate_*_{self.room_id}_*")
            if rate_keys:
                r.delete(*rate_keys)

        except Exception as e:
            print(f"Error clearing Redis data: {e}")

    @database_sync_to_async
    def close_room_db(self):
        """Mark room as closed in database"""
        try:
            room = Room.objects.get(id=self.room_id)
            room.is_closed = True
            room.save()
        except Room.DoesNotExist:
            pass

    # ------------------------------------------------------------------ #
    # History (DB first, then Redis)
    # ------------------------------------------------------------------ #
    async def get_message_history(self, limit=500):
    # 1. DB messages (persistent)
        db_msgs = await self.get_db_messages(limit)

        # Convert DB rows → same shape as Redis
        history = []
        for row in db_msgs:
            created_at = row["created_at"]
            if isinstance(created_at, datetime):
                ts = created_at.timestamp()
            else:
                ts = time.time()

            message_text = (
                row["edited_message"] if row["is_edited"] else row["original_message"]
            )
            if row["is_deleted"]:
                message_text = "[This message was deleted]"

            # Convert UUID to string for JSON serialization
            media_id = row["media_id"]
            if media_id:
                media_id = str(media_id)
            
            # Convert message_id to string if it's UUID
            message_id = row["message_id"]
            if isinstance(message_id, uuid.UUID):
                message_id = str(message_id)

            history.append(
                {
                    "id": message_id,
                    "username": row["username"],
                    "message": message_text,
                    "timestamp": ts,
                    "reactions": {},  # reactions live only in Redis
                    "is_media": row["is_media"],
                    "media_id": media_id or "",
                    "filename": row["filename"] or "",
                    "is_image": row["is_image"],
                    "is_edited": row["is_edited"],
                    "is_deleted": row["is_deleted"],
                    "media_type": row.get("media_type", "once"),  # Add media_type
                }
            )

        # 2. Append any newer Redis-only messages (should be rare)
        redis_key = f"messages_{self.room_id}"
        redis_raw = r.lrange(redis_key, 0, limit - len(history) - 1)
        redis_newer = []
        for raw in redis_raw:
            try:
                msg = json.loads(raw)
                if msg["id"] not in {h["id"] for h in history}:
                    redis_newer.append(msg)
            except:
                continue
        history.extend(redis_newer)

        # Sort by timestamp, oldest first
        history.sort(key=lambda m: m["timestamp"])
        return history[:limit]

    # ------------------------------------------------------------------ #
    # View-once media
    # ------------------------------------------------------------------ #
    async def mark_view_once_media(self, media_id):
        try:
            user = self.user
            media = await database_sync_to_async(TemporaryMedia.objects.get)(
                id=media_id
            )

            if user and user.is_authenticated:
                await database_sync_to_async(media.mark_as_viewed_by_user)(
                    user=user, username=user.username
                )
            else:
                session = self.scope.get("session")
                if session:
                    session_key = session.session_key
                    if session_key:
                        await database_sync_to_async(media.mark_as_viewed_by_user)(
                            session_key=session_key, username=self.username
                        )
        except Exception as e:
            print(f"Error marking media as viewed: {e}")

    # ------------------------------------------------------------------ #
    # Channel-layer receivers
    # ------------------------------------------------------------------ #
    async def chat_message(self, event):
        await self.send(
            text_data=json.dumps(
                {
                    "type": "message",
                    "id": event["id"],
                    "username": event["username"],
                    "message": event["message"],
                    "is_media": event.get("is_media", False),
                    "media_id": event.get("media_id", ""),
                    "filename": event.get("filename", ""),
                    "is_image": event.get("is_image", False),
                }
            )
        )

    async def chat_notification(self, event):
        await self.send(
            text_data=json.dumps(
                {
                    "type": "notification",
                    "message": event["message"],
                }
            )
        )

    async def message_edited(self, event):
        await self.send(
            text_data=json.dumps(
                {
                    "type": "message_edited",
                    "msg_id": event["msg_id"],
                    "message": event["message"],
                    "username": event["username"],
                }
            )
        )

    async def message_deleted(self, event):
        await self.send(
            text_data=json.dumps(
                {
                    "type": "message_deleted",
                    "msg_id": event["msg_id"],
                }
            )
        )

    async def message_unsent(self, event):
        await self.send(
            text_data=json.dumps(
                {
                    "type": "message_unsent",
                    "msg_id": event["msg_id"],
                }
            )
        )

    async def reaction_update(self, event):
        await self.send(
            text_data=json.dumps(
                {
                    "type": "reaction_update",
                    "msg_id": event["msg_id"],
                    "reactions": event["reactions"],
                }
            )
        )

    async def typing_indicator(self, event):
        await self.send(
            text_data=json.dumps(
                {
                    "type": "typing",
                    "username": event["username"],
                }
            )
        )

    async def room_closed(self, event):
        """Handle room closure broadcasts"""
        await self.send(
            text_data=json.dumps(
                {
                    "type": "room_closed",
                    "message": event["message"],
                    "redirect": event.get("redirect", False),
                }
            )
        )

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.room_group_name, self.channel_name)
