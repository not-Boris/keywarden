from django.urls import re_path

from apps.servers.consumers import ShellConsumer

websocket_urlpatterns = [
    re_path(r"^ws/servers/(?P<server_id>\d+)/shell/$", ShellConsumer.as_asgi()),
]
