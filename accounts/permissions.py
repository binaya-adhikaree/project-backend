from rest_framework import permissions
from .models import User, LocationAccess, Location

class IsAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.is_admin)

class IsGastronom(permissions.BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.is_gastronom)

class IsExternal(permissions.BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.is_external)

class IsOwnerOrAdmin(permissions.BasePermission):
   
    def has_object_permission(self, request, view, obj):
        if request.user.is_admin:
            return True
        return obj == request.user

class CanAccessLocation(permissions.BasePermission):
  
    def has_object_permission(self, request, view, obj):
        user = request.user
        if not user or not user.is_authenticated:
            return False
        if user.is_admin:
            return True
        if user.is_gastronom:
            return obj.id == (user.assigned_location.id if user.assigned_location else None)
        if user.is_external:
            return LocationAccess.objects.filter(location=obj, external_user=user, is_active=True).exists()
        return False

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)
