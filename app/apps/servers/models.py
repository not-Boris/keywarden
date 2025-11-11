from __future__ import annotations

from django.core.validators import RegexValidator
from django.db import models
from django.utils.text import slugify


hostname_validator = RegexValidator(
    regex=r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$",
    message="Enter a valid hostname.",
)


class Server(models.Model):
    display_name = models.CharField(max_length=128)
    hostname = models.CharField(max_length=253, null=True, blank=True, unique=True, validators=[hostname_validator])
    ipv4 = models.GenericIPAddressField(null=True, blank=True, protocol="IPv4", unique=True)
    ipv6 = models.GenericIPAddressField(null=True, blank=True, protocol="IPv6", unique=True)
    image = models.ImageField(upload_to="servers/", null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["display_name", "hostname", "ipv4", "ipv6"]
        verbose_name = "Server"
        verbose_name_plural = "Servers"

    def __str__(self) -> str:
        primary = self.hostname or self.ipv4 or self.ipv6 or "unassigned"
        return f"{self.display_name} ({primary})"

    @property
    def image_url(self) -> str | None:
        try:
            return self.image.url if self.image else None
        except Exception:
            return None

    @property
    def initial(self) -> str:
        return (self.display_name or "?").strip()[:1].upper() or "?"


