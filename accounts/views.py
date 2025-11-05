from rest_framework import status, viewsets, permissions
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from django.shortcuts import get_object_or_404
from django.db import transaction

from .models import User, Location, LocationAccess, DocumentUpload, FormSubmission
from .serializers import (
    UserSerializer, UserCreateSerializer, UserUpdateSerializer, ChangePasswordSerializer,
    LoginSerializer, LocationSerializer, LocationAccessSerializer, AssignOperatorSerializer,
    DocumentUploadSerializer, FormSubmissionSerializer
)
from .permissions import IsAdmin, IsGastronom, IsExternal, IsOwnerOrAdmin, CanAccessLocation


class CustomTokenObtainPairView(TokenObtainPairView):
    permission_classes = (AllowAny,)


@api_view(["POST"])
@permission_classes([AllowAny])
def register_view(request):
    serializer = UserCreateSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        refresh = RefreshToken.for_user(user)
        data = {
            "user": UserSerializer(user).data,
            "access": str(refresh.access_token),
            "refresh": str(refresh),
        }
        return Response(data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
@permission_classes([AllowAny])
def login_view(request):
    serializer = LoginSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    user = serializer.validated_data["user"]
    refresh = RefreshToken.for_user(user)
    data = {
        "user": UserSerializer(user).data,
        "access": str(refresh.access_token),
        "refresh": str(refresh)
    }
    return Response(data, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout_view(request):
    refresh_token = request.data.get("refresh")
    if not refresh_token:
        return Response({"detail": "Refresh token required."}, status=status.HTTP_400_BAD_REQUEST)
    try:
        token = RefreshToken(refresh_token)
        token.blacklist()
    except Exception as exc:
        return Response({"detail": "Token invalid or already blacklisted."}, status=status.HTTP_400_BAD_REQUEST)
    return Response({"detail": "Logged out successfully."}, status=status.HTTP_200_OK)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def profile_view(request):
    serializer = UserSerializer(request.user)
    return Response(serializer.data)


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def profile_update_view(request):
    serializer = UserUpdateSerializer(request.user, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response(UserSerializer(request.user).data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def change_password_view(request):
    serializer = ChangePasswordSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    user = request.user
    if not user.check_password(serializer.validated_data["old_password"]):
        return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
    user.set_password(serializer.validated_data["new_password"])
    user.save()
    return Response({"detail": "Password changed successfully."})


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all().order_by("-created_at")
    serializer_class = UserSerializer

    def get_permissions(self):
        if self.action in ["list", "create", "retrieve", "update", "partial_update", "deactivate", "activate", "destroy"]:
            permission_classes = [IsAuthenticated, IsAdmin]
        else:
            permission_classes = [IsAuthenticated]
        return [p() for p in permission_classes]

    def get_serializer_class(self):
        if self.action in ["create"]:
            return UserCreateSerializer
        if self.action in ["partial_update", "update"]:
            return UserUpdateSerializer
        return UserSerializer

    @action(detail=True, methods=["post"], url_path="deactivate")
    def deactivate(self, request, pk=None):
        user = self.get_object()
        user.is_active = False
        user.save(update_fields=["is_active"])
        return Response({"detail": "User deactivated."})

    @action(detail=True, methods=["post"], url_path="activate")
    def activate(self, request, pk=None):
        user = self.get_object()
        user.is_active = True
        user.save(update_fields=["is_active"])
        return Response({"detail": "User activated."})


class LocationViewSet(viewsets.ModelViewSet):
    queryset = Location.objects.all().order_by("-created_at")
    serializer_class = LocationSerializer

    def get_permissions(self):
        if self.action in ["create", "update", "partial_update", "assign_operator", "destroy"]:
            permission_classes = [IsAuthenticated, IsAdmin]
        elif self.action in ["retrieve"]:
            permission_classes = [IsAuthenticated, CanAccessLocation]
        elif self.action in ["list"]:
            permission_classes = [IsAuthenticated]
        else:
            permission_classes = [IsAuthenticated]
        return [p() for p in permission_classes]

    def get_queryset(self):
        user = self.request.user
        if user.is_admin:
            return Location.objects.all()
        if user.is_gastronom:
            if user.assigned_location:
                return Location.objects.filter(id=user.assigned_location.id)
            return Location.objects.none()
        if user.is_external:
            return Location.objects.filter(access_grants__external_user=user, access_grants__is_active=True).distinct()
        return Location.objects.none()

    @action(detail=True, methods=["post"], url_path="assign_operator")
    def assign_operator(self, request, pk=None):
     
        location = self.get_object()
        serializer = AssignOperatorSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        operator_id = serializer.validated_data["operator_id"]
        new_operator = get_object_or_404(User, id=operator_id)
        try:
            with transaction.atomic():
                location.change_operator(new_operator)
        except Exception as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(LocationSerializer(location).data)


class LocationAccessViewSet(viewsets.ModelViewSet):
    queryset = LocationAccess.objects.all().order_by("-granted_at")
    serializer_class = LocationAccessSerializer

    def get_permissions(self):
        if self.action in ["create"]:
            permission_classes = [IsAuthenticated]
        elif self.action in ["list", "retrieve"]:
            permission_classes = [IsAuthenticated]
        elif self.action in ["revoke", "restore"]:
            permission_classes = [IsAuthenticated]
        else:
            permission_classes = [IsAuthenticated, IsAdmin]
        return [p() for p in permission_classes]

    def get_queryset(self):
        user = self.request.user
        if user.is_admin:
            return LocationAccess.objects.all()
        if user.is_gastronom:
            if not user.assigned_location:
                return LocationAccess.objects.none()
            return LocationAccess.objects.filter(location=user.assigned_location)
        if user.is_external:
            return LocationAccess.objects.filter(external_user=user)
        return LocationAccess.objects.none()

    def create(self, request, *args, **kwargs):
       
        user = request.user
        if user.is_external:
            return Response({"detail": "Not allowed."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        location = serializer.validated_data["location"]
        if user.is_gastronom and user.assigned_location and location.id != user.assigned_location.id:
            return Response({"detail": "Gastronom can only grant access to their assigned location."}, status=status.HTTP_403_FORBIDDEN)
        access = serializer.create(serializer.validated_data)
        return Response(LocationAccessSerializer(access).data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"], url_path="revoke")
    def revoke(self, request, pk=None):
        access = self.get_object()
        user = request.user
        if not (user.is_admin or (user.is_gastronom and user.assigned_location and user.assigned_location.id == access.location.id)):
            return Response({"detail": "Not allowed."}, status=status.HTTP_403_FORBIDDEN)
        access.is_active = False
        access.save(update_fields=["is_active"])
        return Response({"detail": "Access revoked."})

    @action(detail=True, methods=["post"], url_path="restore")
    def restore(self, request, pk=None):
        access = self.get_object()
        user = request.user
        if not (user.is_admin or (user.is_gastronom and user.assigned_location and user.assigned_location.id == access.location.id)):
            return Response({"detail": "Not allowed."}, status=status.HTTP_403_FORBIDDEN)
        access.is_active = True
        access.save(update_fields=["is_active"])
        return Response({"detail": "Access restored."})



class DocumentUploadViewSet(viewsets.ModelViewSet):
    queryset = DocumentUpload.objects.all().order_by("-uploaded_at")
    serializer_class = DocumentUploadSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_permissions(self):
        if self.action in ['destroy', 'update', 'partial_update']:
            return [permissions.IsAuthenticated(), IsAdmin()]
        return [permissions.IsAuthenticated()]

    def get_queryset(self):
        """Filter documents based on user role"""
        user = self.request.user
        if user.is_admin:
            return DocumentUpload.objects.all()
        if user.is_gastronom:
            if user.assigned_location:
                return DocumentUpload.objects.filter(location=user.assigned_location)
            return DocumentUpload.objects.none()
        if user.is_external:
            accessible_locations = Location.objects.filter(
                access_grants__external_user=user, 
                access_grants__is_active=True
            )
            return DocumentUpload.objects.filter(location__in=accessible_locations)
        return DocumentUpload.objects.none()

    def perform_create(self, serializer):
        serializer.save(uploaded_by=self.request.user)

    def destroy(self, request, *args, **kwargs):
        """Admin can delete any document"""
        document = self.get_object()
        document.delete()
        return Response(
            {"detail": "Document deleted successfully."},
            status=status.HTTP_200_OK
        )

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated, IsAdmin])
    def toggle_lock(self, request, pk=None):
        """Admin can lock/unlock documents"""
        document = self.get_object()
        document.locked = not document.locked
        document.save()
        return Response({
            'detail': f'Document {"locked" if document.locked else "unlocked"} successfully.',
            'locked': document.locked
        })


class FormSubmissionViewSet(viewsets.ModelViewSet):
    queryset = FormSubmission.objects.all().order_by("-submitted_at")
    serializer_class = FormSubmissionSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_permissions(self):
        """Admin can delete/update, others can only create/read"""
        if self.action in ['destroy', 'update', 'partial_update']:
            return [permissions.IsAuthenticated(), IsAdmin()]
        return [permissions.IsAuthenticated()]

    def get_queryset(self):
        """Filter forms based on user role"""
        user = self.request.user
        if user.is_admin:
            return FormSubmission.objects.all()
        if user.is_gastronom:
            if user.assigned_location:
                return FormSubmission.objects.filter(location=user.assigned_location)
            return FormSubmission.objects.none()
        if user.is_external:
            accessible_locations = Location.objects.filter(
                access_grants__external_user=user,
                access_grants__is_active=True
            )
            return FormSubmission.objects.filter(location__in=accessible_locations)
        return FormSubmission.objects.none()

    def perform_create(self, serializer):
        serializer.save(submitted_by=self.request.user)

    def update(self, request, *args, **kwargs):
        """Admin can update even locked forms"""
        instance = self.get_object()
        
        # Non-admin users cannot edit locked forms
        if not request.user.is_admin and instance.locked:
            return Response(
                {"detail": "Cannot edit locked form. Contact admin."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        return super().update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        """Admin can partially update even locked forms"""
        instance = self.get_object()
        
        # Non-admin users cannot edit locked forms
        if not request.user.is_admin and instance.locked:
            return Response(
                {"detail": "Cannot edit locked form. Contact admin."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        return super().partial_update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        """Admin can delete any form"""
        form = self.get_object()
        form.delete()
        return Response(
            {"detail": "Form deleted successfully."},
            status=status.HTTP_200_OK
        )

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated, IsAdmin])
    def toggle_lock(self, request, pk=None):
        """Admin can lock/unlock forms"""
        form = self.get_object()
        form.locked = not form.locked
        form.save()
        return Response({
            'detail': f'Form {"locked" if form.locked else "unlocked"} successfully.',
            'locked': form.locked
        })