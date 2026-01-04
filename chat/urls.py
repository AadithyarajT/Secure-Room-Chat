# chat/urls.py
from django.urls import path, re_path
from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("rooms/", views.rooms_view, name="rooms"),
    path("direct-messages/", views.my_dm_rooms, name="my_dm_rooms"),
    # Room access - accept both UUID and short codes
    re_path(r"^chat/(?P<room_id>[\w-]+)/$", views.room_view, name="room"),
    # Password verification
    re_path(
        r"^verify-room-password/(?P<room_id>[\w-]+)/$",
        views.verify_room_password,
        name="verify_room_password",
    ),
    path(
        "debug/dm-status/<uuid:room_id>/", views.check_dm_status, name="check_dm_status"
    ),
    # User management
    path("logout/", views.logout_view, name="logout"),
    path("upload-once/", views.upload_once_view_media, name="upload_once"),
    path("media/once/<uuid:media_id>/", views.view_once_media, name="view_once"),
    path("media/check/<uuid:media_id>/", views.get_media_for_view, name="check_media"),
    # Profile Views
    path("profile/", views.profile_view, name="profile"),
    path("profile/edit/", views.profile_edit, name="profile_edit"),
    path("profile/<str:username>/", views.public_profile_view, name="public_profile"),
    path("login/", views.login_view, name="login"),
    path("register/", views.register_view, name="register"),
    # Friends system
    path("friends/", views.friend_list, name="friend_list"),
    path(
        "friends/send-request/", views.send_friend_request, name="send_friend_request"
    ),
    path(
        "friends/respond-request/",
        views.respond_friend_request,
        name="respond_friend_request",
    ),
    path("friends/remove/", views.remove_friend, name="remove_friend"),
    path("friends/cancel/", views.cancel_friend_request, name="cancel_friend_request"),
    # Notifications
    path("notifications/", views.notifications_view, name="notifications"),
    path(
        "notifications/mark-read/",
        views.mark_notification_read,
        name="mark_notification_read",
    ),
    # Complaints
    path("complaint/create/", views.create_complaint, name="create_complaint"),
    path("complaints/", views.view_complaints, name="view_complaints"),
    # API endpoints
    path("api/random-room/", views.get_random_room, name="random_room"),
    path("api/create-dm-room/", views.create_dm_room, name="create_dm_room"),
    path("api/user-stats/", views.user_stats_api, name="user_stats"),
    path(
        "api/forget-access/<uuid:room_id>/",
        views.forget_room_access,
        name="forget_room_access",
    ),
    # Add this line - Private Rooms
    path("my-private-rooms/", views.my_private_rooms, name="my_private_rooms"),
    # In urls.py
    path("api/sidebar-content/", views.get_sidebar_content, name="sidebar_content"),
    # In urls.py
    path(
        "api/check-online-status/",
        views.check_online_status,
        name="check_online_status",
    ),
]
