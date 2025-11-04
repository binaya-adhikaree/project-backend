from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, Location, LocationAccess
from django.utils.translation import gettext_lazy as _

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    readonly_fields = ("created_at", "updated_at") 
    fieldsets = (
        (None, {"fields": ("username", "password")}),
        (_("Personal info"), {"fields": ("first_name", "last_name", "email", "phone", "company_name")}),
        (_("Permissions"), {"fields": ("role", "is_active", "is_staff", "is_superuser", "groups", "user_permissions")}),
        (_("Important dates"), {"fields": ("last_login", "created_at", "updated_at")}),
        (_("Assignment"), {"fields": ("assigned_location",)}),
    )
    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": ("username", "email", "first_name", "last_name", "password1", "password2", "role"),
        }),
    )
    list_display = ("username", "email", "first_name", "last_name", "role", "is_active", "assigned_location")
    list_filter = ("role", "is_active")
    search_fields = ("username", "email", "first_name", "last_name")
    ordering = ("username",)

@admin.register(Location)
class LocationAdmin(admin.ModelAdmin):
    list_display = ("name", "location_id", "current_operator", "city", "postal_code", "is_active")
    search_fields = ("name", "location_id", "address")
    list_filter = ("city", "is_active")

@admin.register(LocationAccess)
class LocationAccessAdmin(admin.ModelAdmin):
    list_display = ("location", "external_user", "granted_by", "granted_at", "is_active")
    search_fields = ("location__name", "external_user__username", "external_user__company_name")
    list_filter = ("is_active",)
