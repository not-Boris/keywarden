from __future__ import annotations

from django.http import HttpRequest, HttpResponse

from .views import disguised_not_found


class DisguiseNotFoundMiddleware:
    """Mask 404 responses with a less-informative alternative."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.get_response(request)
        if getattr(response, "status_code", None) != 404:
            return response
        # Replace all 404 responses, even when DEBUG=True, because Django's
        # handler404 is bypassed in debug mode.
        return disguised_not_found(request)
