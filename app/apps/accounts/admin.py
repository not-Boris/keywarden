from django.contrib import admin

from unfold.admin import ModelAdmin
from unfold.sections import TableSection, TemplateSection

from django.urls import reverse_lazy
from django.utils.translation import gettext_lazy as _

from .models import Account

def __str__(self):
    return f"{self.firstname} {self.lastname}"

# # Register your models here.
# admin.site.register(Account)

# Table for related records
class CustomTableSection(TableSection):
    verbose_name = _("Keywarden Users")  # Displays custom table title
    height = 300  # Force the table height. Ideal for large amount of records
    # related_name = "related_name_set"  # Related model field name
    fields = ["id", "firstname", "lastname", "joined_date"]  # Fields from related model

    # # Custom field
    # def custom_field(self, instance):
    #     return instance.pk

# # Simple template with custom content
# class CardSection(TemplateSection):
#     template_name = "keywarden/some_template.html"

@admin.register(Account)
class SomeAdmin(ModelAdmin):
    list_sections = [
        #CardSection,
        CustomTableSection,
    ]