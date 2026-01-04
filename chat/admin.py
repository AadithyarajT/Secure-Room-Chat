# chat/admin.py
from django.contrib import admin
from .models import (
    Room,
    Profile,
    TemporaryMedia,
    ChatMessage,
    ChatPoll,
    Friendship,
    Notification,
    Complaint,
    MediaView,
    RoomAccess,
    UserRoomAccess,
)


@admin.register(Room)
class RoomAdmin(admin.ModelAdmin):
    list_display = [
        "short_code",
        "name",
        "room_type",
        "is_private",
        "is_closed",
        "created_at",
        "created_by",
    ]
    list_filter = ["room_type", "is_private", "is_closed", "created_at"]
    search_fields = ["short_code", "name"]
    ordering = ["-created_at"]
    readonly_fields = ["id", "short_code", "created_at"]

    # Add this to display participants in admin
    def dm_participants_list(self, obj):
        if obj.room_type == "direct":
            return ", ".join([user.username for user in obj.dm_participants.all()])
        return "N/A"

    dm_participants_list.short_description = "DM Participants"


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ["user", "avatar", "created_at", "updated_at"]
    search_fields = ["user__username"]
    readonly_fields = ["created_at", "updated_at"]


@admin.register(TemporaryMedia)
class TemporaryMediaAdmin(admin.ModelAdmin):
    list_display = [
        "id",
        "uploader_username",
        "room_id",
        "view_count",
        "created_at",
        "expires_at",
    ]
    list_filter = ["created_at"]
    search_fields = ["uploader_username", "room_id"]
    readonly_fields = ["id", "created_at", "expires_at"]
    actions = ["delete_old_media"]

    def view_count(self, obj):
        return obj.user_views.count()

    view_count.short_description = "View Count"

    def delete_old_media(self, request, queryset):
        count = queryset.count()
        for media in queryset:
            media.delete()
        self.message_user(request, f"Successfully deleted {count} media files.")

    delete_old_media.short_description = "Delete selected media files"


@admin.register(ChatMessage)
class ChatMessageAdmin(admin.ModelAdmin):
    list_display = [
        "message_id",
        "username",
        "room_id",
        "is_edited",
        "is_deleted",
        "created_at",
        "updated_at",
    ]
    list_filter = ["is_edited", "is_deleted", "created_at"]
    search_fields = ["username", "room_id", "message_id"]
    readonly_fields = ["created_at", "updated_at"]
    ordering = ["-created_at"]


@admin.register(MediaView)
class MediaViewAdmin(admin.ModelAdmin):
    list_display = ["media", "username", "user", "session_key", "viewed_at"]
    list_filter = ["viewed_at"]
    search_fields = ["username", "media__id", "user__username"]
    readonly_fields = ["viewed_at"]
    ordering = ["-viewed_at"]


@admin.register(ChatPoll)
class ChatPollAdmin(admin.ModelAdmin):
    list_display = [
        "question",
        "room",
        "created_by",
        "is_active",
        "created_at",
        "expires_at",
    ]
    list_filter = ["is_active"]
    search_fields = ["question", "room__name"]
    readonly_fields = ["created_at"]


@admin.register(Friendship)
class FriendshipAdmin(admin.ModelAdmin):
    list_display = ["from_user", "to_user", "status", "created_at"]
    list_filter = ["status"]
    search_fields = ["from_user__username", "to_user__username"]
    readonly_fields = ["created_at"]


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ["user", "notification_type", "title", "is_read", "created_at"]
    list_filter = ["notification_type", "is_read"]
    search_fields = ["user__username", "title"]
    readonly_fields = ["created_at"]


@admin.register(Complaint)
class ComplaintAdmin(admin.ModelAdmin):
    list_display = ["subject", "username", "status", "created_at", "updated_at"]
    list_filter = ["status"]
    search_fields = ["subject", "username"]
    readonly_fields = ["created_at", "updated_at"]


@admin.register(RoomAccess)
class RoomAccessAdmin(admin.ModelAdmin):
    list_display = [
        "room",
        "username",
        "user",
        "ip_address",
        "accessed_at",
        "is_active",
    ]
    list_filter = ["is_active", "accessed_at"]
    search_fields = ["username", "room__name", "ip_address"]
    readonly_fields = ["accessed_at", "last_activity"]
    ordering = ["-accessed_at"]


@admin.register(UserRoomAccess)
class UserRoomAccessAdmin(admin.ModelAdmin):
    list_display = [
        "user",
        "room",
        "granted_at",
        "last_accessed",
        "expires_at",
        "is_valid",
    ]
    list_filter = ["expires_at"]
    search_fields = ["user__username", "room__name"]
    readonly_fields = ["granted_at", "last_accessed"]

    def is_valid(self, obj):
        return obj.is_valid()

    is_valid.boolean = True
    is_valid.short_description = "Valid"


# # chat/admin.py
# from django.contrib import admin
# from .models import (
#     Room,
#     Profile,
#     TemporaryMedia,
#     ChatPoll,
#     Friendship,
#     Notification,
#     Complaint,
#     MediaView,
#     RoomAccess,
#     UserRoomAccess,
# )


# @admin.register(Room)
# class RoomAdmin(admin.ModelAdmin):
#     list_display = [
#         "short_code",
#         "name",
#         "room_type",
#         "is_private",
#         "is_closed",
#         "created_at",
#         "created_by",
#     ]
#     list_filter = ["room_type", "is_private", "is_closed", "created_at"]
#     search_fields = ["short_code", "name"]
#     ordering = ["-created_at"]
#     readonly_fields = ["id", "short_code", "created_at"]

#     # Add this to display participants in admin
#     def dm_participants_list(self, obj):
#         if obj.room_type == "direct":
#             return ", ".join([user.username for user in obj.dm_participants.all()])
#         return "N/A"

#     dm_participants_list.short_description = "DM Participants"


# @admin.register(Profile)
# class ProfileAdmin(admin.ModelAdmin):
#     list_display = ["user", "avatar", "created_at", "updated_at"]
#     search_fields = ["user__username"]
#     readonly_fields = ["created_at", "updated_at"]


# @admin.register(TemporaryMedia)
# class TemporaryMediaAdmin(admin.ModelAdmin):
#     list_display = [
#         "id",
#         "uploader_username",
#         "room_id",
#         "view_count",
#         "created_at",
#         "expires_at",
#     ]
#     list_filter = ["created_at"]
#     search_fields = ["uploader_username", "room_id"]
#     readonly_fields = ["id", "created_at", "expires_at"]
#     actions = ["delete_old_media"]

#     def view_count(self, obj):
#         return obj.user_views.count()

#     view_count.short_description = "View Count"

#     def delete_old_media(self, request, queryset):
#         count = queryset.count()
#         for media in queryset:
#             media.delete()
#         self.message_user(request, f"Successfully deleted {count} media files.")

#     delete_old_media.short_description = "Delete selected media files"


# @admin.register(MediaView)
# class MediaViewAdmin(admin.ModelAdmin):
#     list_display = ["media", "username", "user", "session_key", "viewed_at"]
#     list_filter = ["viewed_at"]
#     search_fields = ["username", "media__id", "user__username"]
#     readonly_fields = ["viewed_at"]
#     ordering = ["-viewed_at"]


# @admin.register(ChatPoll)
# class ChatPollAdmin(admin.ModelAdmin):
#     list_display = [
#         "question",
#         "room",
#         "created_by",
#         "is_active",
#         "created_at",
#         "expires_at",
#     ]
#     list_filter = ["is_active"]
#     search_fields = ["question", "room__name"]
#     readonly_fields = ["created_at"]


# @admin.register(Friendship)
# class FriendshipAdmin(admin.ModelAdmin):
#     list_display = ["from_user", "to_user", "status", "created_at"]
#     list_filter = ["status"]
#     search_fields = ["from_user__username", "to_user__username"]
#     readonly_fields = ["created_at"]


# @admin.register(Notification)
# class NotificationAdmin(admin.ModelAdmin):
#     list_display = ["user", "notification_type", "title", "is_read", "created_at"]
#     list_filter = ["notification_type", "is_read"]
#     search_fields = ["user__username", "title"]
#     readonly_fields = ["created_at"]


# @admin.register(Complaint)
# class ComplaintAdmin(admin.ModelAdmin):
#     list_display = ["subject", "username", "status", "created_at", "updated_at"]
#     list_filter = ["status"]
#     search_fields = ["subject", "username"]
#     readonly_fields = ["created_at", "updated_at"]


# @admin.register(RoomAccess)
# class RoomAccessAdmin(admin.ModelAdmin):
#     list_display = [
#         "room",
#         "username",
#         "user",
#         "ip_address",
#         "accessed_at",
#         "is_active",
#     ]
#     list_filter = ["is_active", "accessed_at"]
#     search_fields = ["username", "room__name", "ip_address"]
#     readonly_fields = ["accessed_at", "last_activity"]
#     ordering = ["-accessed_at"]


# @admin.register(UserRoomAccess)
# class UserRoomAccessAdmin(admin.ModelAdmin):
#     list_display = [
#         "user",
#         "room",
#         "granted_at",
#         "last_accessed",
#         "expires_at",
#         "is_valid",
#     ]
#     list_filter = ["expires_at"]
#     search_fields = ["user__username", "room__name"]
#     readonly_fields = ["granted_at", "last_accessed"]

#     def is_valid(self, obj):
#         return obj.is_valid()

#     is_valid.boolean = True
#     is_valid.short_description = "Valid"
