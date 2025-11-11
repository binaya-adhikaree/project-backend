from rest_framework import status, viewsets, permissions
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from django.shortcuts import get_object_or_404
from django.db import transaction
from datetime import datetime, timedelta
from rest_framework.parsers import MultiPartParser, FormParser
import cloudinary.uploader

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
        "refresh": str(refresh),
        "dashboard": get_user_dashboard_type(user)  # Helper function
    }
    return Response(data, status=status.HTTP_200_OK)


def get_user_dashboard_type(user):
    if user.is_admin:
        return "admin"
    elif user.is_gastronom:
        return "gastronom"
    elif user.is_external:
        return "external"
    return "unknown"


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
    user = request.user
    data = UserSerializer(user).data
    
   
    if user.is_external:
      
        accessible_locations = Location.objects.filter(
            access_grants__external_user=user,
            access_grants__is_active=True
        ).distinct()
        data['accessible_locations'] = LocationSerializer(accessible_locations, many=True).data
    elif user.is_gastronom:
       
        if user.assigned_location:
            data['assigned_location_detail'] = LocationSerializer(user.assigned_location).data
    
    data['dashboard'] = get_user_dashboard_type(user)
    return Response(data)


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
            permission_classes = [IsAuthenticated, (IsAdmin | IsGastronom)]
        else:
            permission_classes = [IsAuthenticated]
        return [p() for p in permission_classes]

    def get_queryset(self):
        user = self.request.user
        if user.is_admin:
            return User.objects.all().order_by("-created_at")
        elif user.is_gastronom:
            # Gastronoms can see all EXTERNAL users to grant access
            return User.objects.filter(role=User.ROLE_EXTERNAL).order_by("-created_at")
        else:
            return User.objects.none()

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
        elif user.is_gastronom:
            if user.assigned_location:
                return Location.objects.filter(id=user.assigned_location.id)
            return Location.objects.none()
        elif user.is_external:
            # External users see only locations they have active access to
            return Location.objects.filter(
                access_grants__external_user=user,
                access_grants__is_active=True
            ).distinct()
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
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """Filter location access based on user role"""
        user = self.request.user
        
        print(f"\n{'='*60}")
        print(f"🔍 GET LOCATION ACCESS QUERYSET")
        print(f"{'='*60}")
        print(f"👤 User: {user.username} (ID: {user.id})")
        print(f"🏷️  Role: {user.role}")
        
        if user.is_admin:
            queryset = LocationAccess.objects.all()
            print(f"👑 Admin - returning all accesses: {queryset.count()} records")
            
        elif user.is_gastronom:
            if not user.assigned_location:
                print("❌ Gastronom has no assigned location")
                return LocationAccess.objects.none()
            
            queryset = LocationAccess.objects.filter(location=user.assigned_location)
            print(f"👨‍🍳 Gastronom - returning accesses for location: {user.assigned_location.name}")
            print(f"   Found {queryset.count()} access records")
            
            # Debug: Show details of each access
            for access in queryset:
                print(f"   - ID: {access.id}")
                print(f"     External User: {access.external_user.username} ({access.external_user.company_name})")
                print(f"     Location: {access.location.name} (ID: {access.location.id})")
                print(f"     Active: {access.is_active}")
                print(f"     Granted: {access.granted_at}")
            
        elif user.is_external:
            queryset = LocationAccess.objects.filter(external_user=user)
            print(f"🏢 External user - returning own accesses: {queryset.count()} records")
            
            # Debug: Show details of each access
            for access in queryset:
                print(f"   - ID: {access.id}")
                print(f"     Location: {access.location.name} (ID: {access.location.id})")
                print(f"     Active: {access.is_active}")
                print(f"     Granted: {access.granted_at}")
                print(f"     Granted by: {access.granted_by.username if access.granted_by else 'N/A'}")
        else:
            queryset = LocationAccess.objects.none()
            print(f"⚠️ Unknown role - returning empty queryset")
        
        print(f"{'='*60}\n")
        return queryset.order_by("-granted_at")

    def list(self, request, *args, **kwargs):
        """List all location accesses for the user"""
        print(f"\n{'='*60}")
        print(f"📋 LIST LOCATION ACCESSES")
        print(f"{'='*60}")
        
        queryset = self.filter_queryset(self.get_queryset())
        
        print(f"📊 Total records to return: {queryset.count()}")
        
        serializer = self.get_serializer(queryset, many=True)
        
        print(f"✅ Serialized {len(serializer.data)} records")
        print(f"{'='*60}\n")
        
        return Response(serializer.data)

    def retrieve(self, request, *args, **kwargs):
        """Retrieve a single location access"""
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        
        print(f"\n📄 Retrieved access ID: {instance.id}")
        print(f"   Location: {instance.location.name}")
        print(f"   External User: {instance.external_user.username}")
        print(f"   Active: {instance.is_active}\n")
        
        return Response(serializer.data)

    def create(self, request, *args, **kwargs):
        """Create new location access (grant access to external user)"""
        user = request.user

        print(f"\n{'='*60}")
        print(f"🔍 CREATE ACCESS REQUEST")
        print(f"{'='*60}")
        print(f"👤 User: {user.username} (ID: {user.id})")
        print(f"🏷️  Role: {user.role}")
        print(f"📦 Request Data: {request.data}")
        print(f"{'='*60}\n")

        # Only Gastronom or Admin can create access
        if user.is_external:
            print("❌ External user attempted to grant access - DENIED")
            return Response(
                {"detail": "External users cannot grant access."},
                status=status.HTTP_403_FORBIDDEN
            )

        data = request.data.copy()

        # Handle Gastronom-specific logic
        if user.is_gastronom:
            print(f"👨‍🍳 Processing Gastronom access grant...")
            
            if not user.assigned_location:
                print("❌ Gastronom has no assigned location")
                return Response(
                    {"detail": "You are not assigned to any location."},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            print(f"📍 Gastronom assigned location: {user.assigned_location.name} (ID: {user.assigned_location.id})")
            
            # If location is provided in request, verify it matches assigned location
            if 'location' in data:
                requested_location_id = int(data['location'])
                print(f"🔍 Requested location ID: {requested_location_id}")
                
                if requested_location_id != user.assigned_location.id:
                    print(f"❌ Location mismatch! Requested: {requested_location_id}, Assigned: {user.assigned_location.id}")
                    return Response(
                        {"detail": "You can only grant access to your assigned location."},
                        status=status.HTTP_403_FORBIDDEN
                    )
                print("✅ Location matches assigned location")
            else:
                # If not provided, set it automatically
                data['location'] = user.assigned_location.id
                print(f"✅ Auto-set location to: {user.assigned_location.id}")

        # Admin can grant access to any location
        if user.is_admin:
            print(f"👑 Admin granting access...")
            if 'location' not in data:
                print("❌ Admin must specify location")
                return Response(
                    {"detail": "Location is required."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            print(f"📍 Admin granting access to location ID: {data['location']}")

        # Validate external_user exists
        if 'external_user' not in data:
            print("❌ External user not specified")
            return Response(
                {"detail": "External user is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            external_user_id = int(data['external_user'])
            external_user = User.objects.get(id=external_user_id)
            print(f"👤 External user: {external_user.username} (ID: {external_user_id})")
            print(f"🏢 Company: {external_user.company_name}")
            
            if external_user.role != User.ROLE_EXTERNAL:
                print(f"❌ User role is {external_user.role}, not EXTERNAL")
                return Response(
                    {"detail": "Selected user is not an external user."},
                    status=status.HTTP_400_BAD_REQUEST
                )
        except User.DoesNotExist:
            print(f"❌ External user with ID {data.get('external_user')} not found")
            return Response(
                {"detail": "External user not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        except (ValueError, TypeError) as e:
            print(f"❌ Invalid external_user ID: {e}")
            return Response(
                {"detail": "Invalid external user ID."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate location exists
        try:
            location_id = int(data['location'])
            location = Location.objects.get(id=location_id)
            print(f"📍 Location validated: {location.name} (ID: {location_id})")
        except Location.DoesNotExist:
            print(f"❌ Location with ID {data.get('location')} not found")
            return Response(
                {"detail": "Location not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        except (ValueError, TypeError) as e:
            print(f"❌ Invalid location ID: {e}")
            return Response(
                {"detail": "Invalid location ID."},
                status=status.HTTP_400_BAD_REQUEST
            )

        print(f"\n📋 Final data being sent to serializer:")
        print(f"   - Location: {data.get('location')} ({location.name})")
        print(f"   - External User: {data.get('external_user')} ({external_user.username})")
        print()

        serializer = self.get_serializer(data=data)
        
        try:
            serializer.is_valid(raise_exception=True)
            print("✅ Serializer validation passed")
        except Exception as e:
            print(f"❌ Serializer validation failed: {e}")
            print(f"   Errors: {serializer.errors}")
            raise

        self.perform_create(serializer)
        
        print(f"\n{'='*60}")
        print(f"✅ ACCESS GRANTED SUCCESSFULLY")
        print(f"{'='*60}")
        print(f"📄 Response data: {serializer.data}")
        print(f"{'='*60}\n")
        
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        """Set granted_by to current user when creating access"""
        user = self.request.user
        print(f"💾 Saving access with granted_by: {user.username}")
        serializer.save(granted_by=user)

    def update(self, request, *args, **kwargs):
        """Update location access (not typically used)"""
        print(f"\n⚠️  UPDATE called on LocationAccess - this is unusual")
        return super().update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        """Partial update location access (not typically used)"""
        print(f"\n⚠️  PARTIAL_UPDATE called on LocationAccess - this is unusual")
        return super().partial_update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        """Delete location access (Admin only - prefer revoke instead)"""
        user = request.user
        instance = self.get_object()
        
        print(f"\n{'='*60}")
        print(f"🗑️  DELETE ACCESS REQUEST")
        print(f"{'='*60}")
        print(f"👤 User: {user.username}")
        print(f"🏷️  Role: {user.role}")
        print(f"📄 Access ID: {instance.id}")
        print(f"   Location: {instance.location.name}")
        print(f"   External User: {instance.external_user.username}")
        
        if not user.is_admin:
            print("❌ Only admins can delete access records")
            print(f"{'='*60}\n")
            return Response(
                {"detail": "Only administrators can delete access records. Use revoke instead."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        print("✅ Admin deleting access record")
        print(f"{'='*60}\n")
        
        return super().destroy(request, *args, **kwargs)

    @action(detail=True, methods=["post"], url_path="revoke")
    def revoke(self, request, pk=None):
        """Revoke access (set is_active to False)"""
        access = self.get_object()
        user = request.user

        print(f"\n{'='*60}")
        print(f"🚫 REVOKE ACCESS REQUEST")
        print(f"{'='*60}")
        print(f"👤 User: {user.username} (ID: {user.id})")
        print(f"🏷️  Role: {user.role}")
        print(f"📄 Access ID: {access.id}")
        print(f"   Location: {access.location.name} (ID: {access.location.id})")
        print(f"   External User: {access.external_user.username}")
        print(f"   Current Status: {'Active' if access.is_active else 'Revoked'}")

        # Check permissions
        has_permission = False
        
        if user.is_admin:
            print("✅ Admin can revoke any access")
            has_permission = True
        elif user.is_gastronom:
            if user.assigned_location and user.assigned_location.id == access.location.id:
                print(f"✅ Gastronom can revoke access for their location")
                has_permission = True
            else:
                print(f"❌ Gastronom can only revoke access for their assigned location")
                print(f"   Assigned: {user.assigned_location.name if user.assigned_location else 'None'}")
                print(f"   Attempted: {access.location.name}")

        if not has_permission:
            print(f"{'='*60}\n")
            return Response(
                {"detail": "You don't have permission to revoke this access."},
                status=status.HTTP_403_FORBIDDEN
            )

        if not access.is_active:
            print("⚠️  Access is already revoked")
            print(f"{'='*60}\n")
            return Response(
                {"detail": "Access is already revoked."},
                status=status.HTTP_400_BAD_REQUEST
            )

        access.is_active = False
        access.save(update_fields=["is_active"])
        
        print("✅ Access revoked successfully")
        print(f"{'='*60}\n")
        
        return Response(
            {
                "detail": "Access revoked successfully.",
                "access": LocationAccessSerializer(access).data
            },
            status=status.HTTP_200_OK
        )

    @action(detail=True, methods=["post"], url_path="restore")
    def restore(self, request, pk=None):
        """Restore access (set is_active to True)"""
        access = self.get_object()
        user = request.user

        print(f"\n{'='*60}")
        print(f"♻️  RESTORE ACCESS REQUEST")
        print(f"{'='*60}")
        print(f"👤 User: {user.username} (ID: {user.id})")
        print(f"🏷️  Role: {user.role}")
        print(f"📄 Access ID: {access.id}")
        print(f"   Location: {access.location.name} (ID: {access.location.id})")
        print(f"   External User: {access.external_user.username}")
        print(f"   Current Status: {'Active' if access.is_active else 'Revoked'}")

        # Check permissions
        has_permission = False
        
        if user.is_admin:
            print("✅ Admin can restore any access")
            has_permission = True
        elif user.is_gastronom:
            if user.assigned_location and user.assigned_location.id == access.location.id:
                print(f"✅ Gastronom can restore access for their location")
                has_permission = True
            else:
                print(f"❌ Gastronom can only restore access for their assigned location")
                print(f"   Assigned: {user.assigned_location.name if user.assigned_location else 'None'}")
                print(f"   Attempted: {access.location.name}")

        if not has_permission:
            print(f"{'='*60}\n")
            return Response(
                {"detail": "You don't have permission to restore this access."},
                status=status.HTTP_403_FORBIDDEN
            )

        if access.is_active:
            print("⚠️  Access is already active")
            print(f"{'='*60}\n")
            return Response(
                {"detail": "Access is already active."},
                status=status.HTTP_400_BAD_REQUEST
            )

        access.is_active = True
        access.granted_by = user  # Update who restored it
        access.save(update_fields=["is_active", "granted_by"])
        
        print("✅ Access restored successfully")
        print(f"{'='*60}\n")
        
        return Response(
            {
                "detail": "Access restored successfully.",
                "access": LocationAccessSerializer(access).data
            },
            status=status.HTTP_200_OK
        )

    @action(detail=False, methods=["get"], url_path="my-access")
    def my_access(self, request):
        """Get current user's location accesses (for external users)"""
        user = request.user
        
        print(f"\n{'='*60}")
        print(f"👤 MY ACCESS REQUEST")
        print(f"{'='*60}")
        print(f"User: {user.username}")
        print(f"Role: {user.role}")
        
        if not user.is_external:
            print("⚠️  Only external users can use this endpoint")
            print(f"{'='*60}\n")
            return Response(
                {"detail": "This endpoint is only for external users."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        accesses = LocationAccess.objects.filter(
            external_user=user,
            is_active=True
        ).select_related('location', 'granted_by')
        
        print(f"📊 Found {accesses.count()} active accesses")
        
        for access in accesses:
            print(f"   - {access.location.name} (granted {access.granted_at})")
        
        print(f"{'='*60}\n")
        
        serializer = self.get_serializer(accesses, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=["get"], url_path="by-location/(?P<location_id>[^/.]+)")
    def by_location(self, request, location_id=None):
        """Get all accesses for a specific location (Admin/Gastronom only)"""
        user = request.user
        
        print(f"\n{'='*60}")
        print(f"📍 ACCESS BY LOCATION REQUEST")
        print(f"{'='*60}")
        print(f"User: {user.username}")
        print(f"Role: {user.role}")
        print(f"Location ID: {location_id}")
        
        try:
            location = Location.objects.get(id=location_id)
            print(f"Location: {location.name}")
        except Location.DoesNotExist:
            print("❌ Location not found")
            print(f"{'='*60}\n")
            return Response(
                {"detail": "Location not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check permissions
        if user.is_external:
            print("❌ External users cannot access this endpoint")
            print(f"{'='*60}\n")
            return Response(
                {"detail": "You don't have permission to view this."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        if user.is_gastronom:
            if not user.assigned_location or user.assigned_location.id != location.id:
                print("❌ Gastronom can only view accesses for their assigned location")
                print(f"{'='*60}\n")
                return Response(
                    {"detail": "You can only view accesses for your assigned location."},
                    status=status.HTTP_403_FORBIDDEN
                )
        
        accesses = LocationAccess.objects.filter(
            location=location
        ).select_related('external_user', 'granted_by')
        
        print(f"📊 Found {accesses.count()} accesses for this location")
        print(f"{'='*60}\n")
        
        serializer = self.get_serializer(accesses, many=True)
        return Response(serializer.data)



class DocumentUploadViewSet(viewsets.ModelViewSet):
    queryset = DocumentUpload.objects.all().order_by("-uploaded_at")
    serializer_class = DocumentUploadSerializer
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def get_permissions(self):
     
        if self.action in ['destroy', 'update', 'partial_update']:
            return [permissions.IsAuthenticated(), IsAdmin()]
        return [permissions.IsAuthenticated()]

    def get_queryset(self):

        user = self.request.user
        
        if user.is_admin:
            queryset = DocumentUpload.objects.all()
        elif user.is_gastronom:
            if user.assigned_location:
                queryset = DocumentUpload.objects.filter(location=user.assigned_location)
            else:
                return DocumentUpload.objects.none()
        elif user.is_external:
    
            accessible_locations = Location.objects.filter(
                access_grants__external_user=user, 
                access_grants__is_active=True
            )
            queryset = DocumentUpload.objects.filter(location__in=accessible_locations)
        else:
            return DocumentUpload.objects.none()
        
        
        location_id = self.request.query_params.get('location', None)
        if location_id is not None:
            queryset = queryset.filter(location_id=location_id)
        
        return queryset.order_by("-uploaded_at")

    def create(self, request, *args, **kwargs):
        """Handle document upload"""
        user = request.user
        file = request.FILES.get('file')
        
        if not file:
            return Response(
                {"error": "No file provided"},
                status=status.HTTP_400_BAD_REQUEST
            )

        location_id = request.data.get('location')
        section = request.data.get('section')

        if not location_id or not section:
            return Response(
                {"error": "Location and section are required"},
                status=status.HTTP_400_BAD_REQUEST
            )

      
        try:
            location = Location.objects.get(id=location_id)
            
            if user.is_external:
             
                has_access = LocationAccess.objects.filter(
                    location=location,
                    external_user=user,
                    is_active=True
                ).exists()
                
                if not has_access:
                    return Response(
                        {"error": "You don't have access to upload to this location"},
                        status=status.HTTP_403_FORBIDDEN
                    )
            elif user.is_gastronom:
            
                if not user.assigned_location or user.assigned_location.id != location.id:
                    return Response(
                        {"error": "You can only upload to your assigned location"},
                        status=status.HTTP_403_FORBIDDEN
                    )
        except Location.DoesNotExist:
            return Response(
                {"error": "Location not found"},
                status=status.HTTP_404_NOT_FOUND
            )

 
        allowed_types = [
            'application/pdf', 
            'image/jpeg', 
            'image/png', 
            'image/jpg',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        ]
        max_size = 10 * 1024 * 1024  # 10MB

        if file.content_type not in allowed_types:
            return Response(
                {"error": f"File type not allowed. Allowed: PDF, Images, Word docs"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if file.size > max_size:
            return Response(
                {"error": f"File too large. Maximum size is 10MB"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            is_image = file.content_type.startswith('image/')
            resource_type = "image" if is_image else "raw"
            
    
            

            upload_result = cloudinary.uploader.upload(
                file,
                resource_type=resource_type,
                folder="documents",
                unique_filename=True,
                invalidate=True,
                type="upload",       
                access_mode="public"
            )
            
        
            
            document = DocumentUpload.objects.create(
                location=location,
                section=section,
                file=upload_result['public_id'],
                uploaded_by=user,
                resource_type=resource_type
            )

            serializer = self.get_serializer(document)
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        except Exception as e:
            print(f"❌ Upload error: {str(e)}")
            import traceback
            traceback.print_exc()
            return Response(
                {"error": f"Upload failed: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    def destroy(self, request, *args, **kwargs):
        document = self.get_object()
        
     
        try:
            if document.file:
                file_str = str(document.file)
                
                if '/upload/' in file_str:
                    public_id = file_str.split('/upload/')[-1]
                else:
                    public_id = file_str
                
                print(f"🗑️ Deleting: {public_id}")
                
                result = cloudinary.uploader.destroy(
                    public_id,
                    resource_type=document.resource_type,
                    invalidate=True
                )
                if result.get('result') == 'ok':
                    print(f"✅ Deleted from Cloudinary")
                    
        except Exception as e:
            print(f"⚠️ Cloudinary delete error: {e}")
        
        document.delete()
        return Response(
            {"detail": "Document deleted successfully."},
            status=status.HTTP_200_OK
        )

    @action(detail=True, methods=['post'], permission_classes=[permissions.IsAuthenticated, IsAdmin])
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
        if self.action in ['destroy', 'update', 'partial_update']:
            return [permissions.IsAuthenticated(), IsAdmin()]
        return [permissions.IsAuthenticated()]

    def get_queryset(self):
        user = self.request.user
        queryset = FormSubmission.objects.all()
        
        # Filter by location if provided
        location_id = self.request.query_params.get('location', None)
        if location_id is not None:
            queryset = queryset.filter(location_id=location_id)
        
        if user.is_admin:
            return queryset
        elif user.is_gastronom:
            if user.assigned_location:
                return queryset.filter(location=user.assigned_location)
            return FormSubmission.objects.none()
        elif user.is_external:
            accessible_locations = Location.objects.filter(
                access_grants__external_user=user,
                access_grants__is_active=True
            )
            return queryset.filter(location__in=accessible_locations)
        return FormSubmission.objects.none()

    def perform_create(self, serializer):
        serializer.save(submitted_by=self.request.user)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        
        if not request.user.is_admin and instance.locked:
            return Response(
                {"detail": "Cannot edit locked form. Contact admin."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        return super().update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        instance = self.get_object()
        
        if not request.user.is_admin and instance.locked:
            return Response(
                {"detail": "Cannot edit locked form. Contact admin."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        return super().partial_update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        form = self.get_object()
        form.delete()
        return Response(
            {"detail": "Form deleted successfully."},
            status=status.HTTP_200_OK
        )

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated, IsAdmin])
    def toggle_lock(self, request, pk=None):
        form = self.get_object()
        form.locked = not form.locked
        form.save()
        return Response({
            'detail': f'Form {"locked" if form.locked else "unlocked"} successfully.',
            'locked': form.locked
        })