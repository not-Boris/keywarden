# apps/dashboard/admin.py
from django.contrib import admin

from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.admin import GroupAdmin as BaseGroupAdmin
from django.contrib.auth.models import User, Group

from unfold.forms import AdminPasswordChangeForm, UserChangeForm, UserCreationForm
from unfold.admin import ModelAdmin


# Unregister the default Group admin and register with Unfold
try:
    admin.site.unregister(Group)
    admin.site.unregister(User)
except admin.sites.NotRegistered:
    pass

@admin.register(User)
class UserAdmin(BaseUserAdmin, ModelAdmin):
    # Forms loaded from `unfold.forms`
    form = UserChangeForm
    add_form = UserCreationForm
    change_password_form = AdminPasswordChangeForm


@admin.register(Group)
class GroupAdmin(BaseGroupAdmin, ModelAdmin):
    pass


# # Custom dashboard view
# def custom_dashboard(request):
#     context = {
#         "user_count": get_user_model().objects.count(),
#         "group_count": auth_models.Group.objects.count(),
#     }
#     return render(request, "unfold/dashboard.html", context)


# # Add the URL to admin
# admin.site.get_urls = (
#     lambda self: [path("", custom_dashboard, name="index")] + self.get_urls()
# ).__get__(admin.site)