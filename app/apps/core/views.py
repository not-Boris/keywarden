from __future__ import annotations

from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse
from django.urls import reverse
from django.views.decorators.cache import never_cache


@never_cache
def disguised_not_found(request: HttpRequest, exception=None) -> HttpResponse:
    """Return a less-informative response for unknown endpoints."""
    path = request.path or ""
    accepts = (request.META.get("HTTP_ACCEPT") or "").lower()
    # Treat anything that looks API-like as a probe and return a generic
    # auth-style response rather than a 404 page.
    is_api_like = path.startswith("/api/") or "application/json" in accepts

    if is_api_like:
        # Avoid a 404 response for unknown API paths.
        return JsonResponse({"detail": "Unauthorized."}, status=401)

    try:
        # For browser traffic, redirect to a known entry point so the
        # response shape is predictable and uninformative.
        target = reverse("servers:dashboard")
    except Exception:
        target = "/"
    return HttpResponseRedirect(target)
