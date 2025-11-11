from django.contrib import admin
from django.contrib.auth.models import User
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from unfold.admin import ModelAdmin


class UnfoldUserAdmin(DjangoUserAdmin, ModelAdmin):
    list_display = DjangoUserAdmin.list_display + ("last_login", "date_joined")
    readonly_fields = ("last_login", "date_joined")
    ordering = ("-date_joined",)


# Unregister the default User admin and register with Unfold
try:
    admin.site.unregister(User)
except admin.sites.NotRegistered:
    pass

admin.site.register(User, UnfoldUserAdmin)