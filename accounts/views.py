from rest_framework import status, viewsets, mixins,permissions
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from django.shortcuts import get_object_or_404
from django.db import transaction


from .models import User, Location, LocationAccess
from .serializers import (
    UserSerializer, UserCreateSerializer, UserUpdateSerializer, ChangePasswordSerializer,
    LoginSerializer, LocationSerializer, LocationAccessSerializer, AssignOperatorSerializer
)
from .permissions import IsAdmin, IsGastronom, IsExternal, IsOwnerOrAdmin, CanAccessLocation

from .models import DocumentUpload, FormSubmission
from .serializers import DocumentUploadSerializer, FormSubmissionSerializer


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
    """
    Blacklist refresh token on logout.
    Body: { "refresh": "<token>" }
    """
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
        # list/create/etc restricted: only ADMIN
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
        """
        ADMIN only - change operator for a location.
        Body: { operator_id: <id> }
        """
        location = self.get_object()
        serializer = AssignOperatorSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        operator_id = serializer.validated_data["operator_id"]
        new_operator = get_object_or_404(User, id=operator_id)
        # Only admin allowed here (permission already enforced)
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
            permission_classes = [IsAuthenticated]  # further checks in create()
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
            # grants for their assigned location
            if not user.assigned_location:
                return LocationAccess.objects.none()
            return LocationAccess.objects.filter(location=user.assigned_location)
        if user.is_external:
            return LocationAccess.objects.filter(external_user=user)
        return LocationAccess.objects.none()

    def create(self, request, *args, **kwargs):
        """
        GASTRONOM: can grant access to their location only.
        ADMIN: can grant to any location.
        EXTERNAL: cannot create grants.
        """
        user = request.user
        if user.is_external:
            return Response({"detail": "Not allowed."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        location = serializer.validated_data["location"]
        external_user = serializer.validated_data["external_user"]
        if user.is_gastronom and user.assigned_location and location.id != user.assigned_location.id:
            return Response({"detail": "Gastronom can only grant access to their assigned location."}, status=status.HTTP_403_FORBIDDEN)
        # create or restore access
        access = serializer.create(serializer.validated_data)
        return Response(LocationAccessSerializer(access).data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"], url_path="revoke")
    def revoke(self, request, pk=None):
        access = self.get_object()
        # Only admin or gastronom of that location can revoke
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

    def perform_create(self, serializer):
        serializer.save(uploaded_by=self.request.user)


class FormSubmissionViewSet(viewsets.ModelViewSet):
    queryset = FormSubmission.objects.all().order_by("-submitted_at")
    serializer_class = FormSubmissionSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(submitted_by=self.request.user)