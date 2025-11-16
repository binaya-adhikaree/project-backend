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
from django.conf import settings

from .models import Subscription
from .serializers import SubscriptionSerializer
import stripe

from .models import User, Location, LocationAccess, DocumentUpload, FormSubmission
from .serializers import (
    UserSerializer, UserCreateSerializer, UserUpdateSerializer, ChangePasswordSerializer,
    LoginSerializer, LocationSerializer, LocationAccessSerializer, AssignOperatorSerializer,
    DocumentUploadSerializer, FormSubmissionSerializer
)
from .permissions import IsAdmin, IsGastronom, IsExternal, IsOwnerOrAdmin, CanAccessLocation

from django.utils import timezone
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

def check_gastronom_subscription(user, location):
    """Check if gastronom has active subscription for location"""
    if not user.is_gastronom:
        return True  # External users don't need subscription
    
    try:
        subscription = Subscription.objects.get(
            gastronom=user,
            location=location
        )
        return subscription.can_upload
    except Subscription.DoesNotExist:
        return False



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
        "dashboard": get_user_dashboard_type(user)
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
            
            # Include subscription info for Gastronom
            try:
                subscription = Subscription.objects.get(
                    gastronom=user,
                    location=user.assigned_location
                )
                data['subscription'] = SubscriptionSerializer(subscription).data
            except Subscription.DoesNotExist:
                data['subscription'] = None
    
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
   
        user = self.request.user
        
        if user.is_admin:
            queryset = LocationAccess.objects.all()
         
            
        elif user.is_gastronom:
            if not user.assigned_location:
              
                return LocationAccess.objects.none()
            
            queryset = LocationAccess.objects.filter(location=user.assigned_location)
        
            
         
            for access in queryset:
                print(f"   - ID: {access.id}")
                print(f"     External User: {access.external_user.username} ({access.external_user.company_name})")
                print(f"     Location: {access.location.name} (ID: {access.location.id})")
                print(f"     Active: {access.is_active}")
                print(f"     Granted: {access.granted_at}")
            
        elif user.is_external:
            queryset = LocationAccess.objects.filter(external_user=user)
            print(f"🏢 External user - returning own accesses: {queryset.count()} records")
            
           
            for access in queryset:
                print(f"   - ID: {access.id}")
                print(f"     Location: {access.location.name} (ID: {access.location.id})")
                print(f"     Active: {access.is_active}")
                print(f"     Granted: {access.granted_at}")
                print(f"     Granted by: {access.granted_by.username if access.granted_by else 'N/A'}")
        else:
            queryset = LocationAccess.objects.none()
           
        
       
        return queryset.order_by("-granted_at")

    def list(self, request, *args, **kwargs):
      
      
        queryset = self.filter_queryset(self.get_queryset())
        
       
        serializer = self.get_serializer(queryset, many=True)
        
        
        
        return Response(serializer.data)

    def retrieve(self, request, *args, **kwargs):
       
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        
       
        
        return Response(serializer.data)

    def create(self, request, *args, **kwargs):
       
        user = request.user


      
        if user.is_external:
          
            return Response(
                {"detail": "External users cannot grant access."},
                status=status.HTTP_403_FORBIDDEN
            )

        data = request.data.copy()

        
        if user.is_gastronom:
           
            
            if not user.assigned_location:
                return Response(
                    {"detail": "You are not assigned to any location."},
                    status=status.HTTP_403_FORBIDDEN
                )
            
          
            
           
            if 'location' in data:
                requested_location_id = int(data['location'])
           
                
                if requested_location_id != user.assigned_location.id:
            
                    return Response(
                        {"detail": "You can only grant access to your assigned location."},
                        status=status.HTTP_403_FORBIDDEN
                    )
                
            else:
               
                data['location'] = user.assigned_location.id
                

   
        if user.is_admin:
        
            if 'location' not in data:
               
                return Response(
                    {"detail": "Location is required."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            print(f"📍 Admin granting access to location ID: {data['location']}")

       
        if 'external_user' not in data:
           
            return Response(
                {"detail": "External user is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            external_user_id = int(data['external_user'])
            external_user = User.objects.get(id=external_user_id)
          
            
            if external_user.role != User.ROLE_EXTERNAL:
         
                return Response(
                    {"detail": "Selected user is not an external user."},
                    status=status.HTTP_400_BAD_REQUEST
                )
        except User.DoesNotExist:
           
            return Response(
                {"detail": "External user not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        except (ValueError, TypeError) as e:
           
            return Response(
                {"detail": "Invalid external user ID."},
                status=status.HTTP_400_BAD_REQUEST
            )

        
        try:
            location_id = int(data['location'])
            location = Location.objects.get(id=location_id)

        except Location.DoesNotExist:
    
            return Response(
                {"detail": "Location not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        except (ValueError, TypeError) as e:
            
            return Response(
                {"detail": "Invalid location ID."},
                status=status.HTTP_400_BAD_REQUEST
            )

    
        serializer = self.get_serializer(data=data)
        
        try:
            serializer.is_valid(raise_exception=True)
        except Exception as e:
            raise

        self.perform_create(serializer)
        
      
        
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        user = self.request.user
        serializer.save(granted_by=user)

    def update(self, request, *args, **kwargs):
        return super().update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        return super().partial_update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
      
        user = request.user
        instance = self.get_object()
        
      
        if not user.is_admin:
            
            return Response(
                {"detail": "Only administrators can delete access records. Use revoke instead."},
                status=status.HTTP_403_FORBIDDEN
            )
        
   
        
        return super().destroy(request, *args, **kwargs)

    @action(detail=True, methods=["post"], url_path="revoke")
    def revoke(self, request, pk=None):
        """Revoke access (set is_active to False)"""
        access = self.get_object()
        user = request.user

       
        has_permission = False
        
        if user.is_admin:
            
            has_permission = True
        elif user.is_gastronom:
            if user.assigned_location and user.assigned_location.id == access.location.id:
               
                has_permission = True
            else:
                print(f"❌ Gastronom can only revoke access for their assigned location")
                print(f"   Assigned: {user.assigned_location.name if user.assigned_location else 'None'}")
                print(f"   Attempted: {access.location.name}")

        if not has_permission:
         
            return Response(
                {"detail": "You don't have permission to revoke this access."},
                status=status.HTTP_403_FORBIDDEN
            )

        if not access.is_active:
           
            return Response(
                {"detail": "Access is already revoked."},
                status=status.HTTP_400_BAD_REQUEST
            )

        access.is_active = False
        access.save(update_fields=["is_active"])
      
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

    
        has_permission = False
        
        if user.is_admin:
            has_permission = True
        elif user.is_gastronom:
            if user.assigned_location and user.assigned_location.id == access.location.id:
                
                has_permission = True
            else:
                print(f"❌ Gastronom can only restore access for their assigned location")
                print(f"   Assigned: {user.assigned_location.name if user.assigned_location else 'None'}")
                print(f"   Attempted: {access.location.name}")

        if not has_permission:
           
            return Response(
                {"detail": "You don't have permission to restore this access."},
                status=status.HTTP_403_FORBIDDEN
            )

        if access.is_active:
            return Response(
                {"detail": "Access is already active."},
                status=status.HTTP_400_BAD_REQUEST
            )

        access.is_active = True
        access.granted_by = user 
        access.save(update_fields=["is_active", "granted_by"])
        
       
        
        return Response(
            {
                "detail": "Access restored successfully.",
                "access": LocationAccessSerializer(access).data
            },
            status=status.HTTP_200_OK
        )

    @action(detail=False, methods=["get"], url_path="my-access")
    def my_access(self, request):
       
        user = request.user
        
        if not user.is_external:
          
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
      
        user = request.user
        
     
        try:
            location = Location.objects.get(id=location_id)
        except Location.DoesNotExist:
            return Response(
                {"detail": "Location not found."},
                status=status.HTTP_404_NOT_FOUND
            )
       
        if user.is_external:
            return Response(
                {"detail": "You don't have permission to view this."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        if user.is_gastronom:
            if not user.assigned_location or user.assigned_location.id != location.id:
                return Response(
                    {"detail": "You can only view accesses for your assigned location."},
                    status=status.HTTP_403_FORBIDDEN
                )
        
        accesses = LocationAccess.objects.filter(
            location=location
        ).select_related('external_user', 'granted_by')
        
     
        
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
        """Handle document upload with subscription check"""
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
      
            if user.is_gastronom:
                if not check_gastronom_subscription(user, location):
                    return Response(
                        {
                            "error": "Your subscription is inactive. Please renew to upload documents.",
                            "subscription_required": True
                        },
                        status=status.HTTP_402_PAYMENT_REQUIRED
                    )

            
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
                
                result = cloudinary.uploader.destroy(
                    public_id,
                    resource_type=document.resource_type,
                    invalidate=True
                )
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

    def create(self, request, *args, **kwargs):
        """Handle form submission with subscription check"""
        user = request.user
        location_id = request.data.get('location')
        
        if not location_id:
            return Response(
                {"error": "Location is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            location = Location.objects.get(id=location_id)
            
           
            if user.is_gastronom:
                if not check_gastronom_subscription(user, location):
                    return Response(
                        {
                            "error": "Your subscription is inactive. Please renew to submit forms.",
                            "subscription_required": True
                        },
                        status=status.HTTP_402_PAYMENT_REQUIRED
                    )
            
          
            if user.is_external:
                has_access = LocationAccess.objects.filter(
                    location=location,
                    external_user=user,
                    is_active=True
                ).exists()
                
                if not has_access:
                    return Response(
                        {"error": "You don't have access to this location"},
                        status=status.HTTP_403_FORBIDDEN
                    )
            elif user.is_gastronom:
                if not user.assigned_location or user.assigned_location.id != location.id:
                    return Response(
                        {"error": "You can only submit forms for your assigned location"},
                        status=status.HTTP_403_FORBIDDEN
                    )
                    
        except Location.DoesNotExist:
            return Response(
                {"error": "Location not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        
    
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

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



class SubscriptionViewSet(viewsets.ModelViewSet):
    queryset = Subscription.objects.all()
    serializer_class = SubscriptionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
     
        user = self.request.user
        if user.is_admin:
            return Subscription.objects.all()
        elif user.is_gastronom:
            return Subscription.objects.filter(gastronom=user)
        return Subscription.objects.none()

    @action(detail=False, methods=['get'], url_path='my-subscription')
    def my_subscription(self, request):
        user = request.user
        
        if not user.is_gastronom:
            return Response(
                {"detail": "Only Gastronom users have subscriptions."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            subscription = Subscription.objects.get(gastronom=user)
            serializer = self.get_serializer(subscription)
            return Response(serializer.data)
        except Subscription.DoesNotExist:
            return Response(
                {"detail": "No subscription found."},
                status=status.HTTP_404_NOT_FOUND
            )

    @action(detail=False, methods=['post'], url_path='create-checkout-session')
    def create_checkout_session(self, request):
        
        user = request.user
        
        if not user.is_gastronom:
            return Response(
                {"detail": "Only Gastronom users can subscribe."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        plan_type = request.data.get('plan_type', 'MONTHLY')
        location_id = request.data.get('location_id')
        
        if not location_id:
            return Response(
                {"detail": "Location ID is required."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            location = Location.objects.get(id=location_id)
            
            if user.assigned_location and user.assigned_location.id != location.id:
                return Response(
                    {"detail": "You can only subscribe for your assigned location."},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            subscription, created = Subscription.objects.get_or_create(
                gastronom=user,
                location=location,
                defaults={'plan_type': plan_type}
            )
            
            if not subscription.stripe_customer_id:
                customer = stripe.Customer.create(
                    email=user.email,
                    name=f"{user.first_name} {user.last_name}",
                    metadata={
                        'user_id': user.id,
                        'location_id': location.id
                    }
                )
                subscription.stripe_customer_id = customer.id
                subscription.save()
            
           
            if plan_type == 'MONTHLY':
                price_id = settings.STRIPE_MONTHLY_PRICE_ID
            else:
                price_id = settings.STRIPE_YEARLY_PRICE_ID
            
    
            checkout_session = stripe.checkout.Session.create(
                customer=subscription.stripe_customer_id,
                payment_method_types=['card'],
                line_items=[{
                    'price': price_id,
                    'quantity': 1,
                }],
                mode='subscription',
                success_url=f"{settings.FRONTEND_URL}/dashboard/subscription/success?session_id={{CHECKOUT_SESSION_ID}}",
                cancel_url=f"{settings.FRONTEND_URL}/dashboard/subscription",
                metadata={
                    'user_id': user.id,
                    'location_id': location.id,
                    'plan_type': plan_type
                }
            )
            
            return Response({
                'checkout_url': checkout_session.url,
                'session_id': checkout_session.id
            })
            
        except Location.DoesNotExist:
            return Response(
                {"detail": "Location not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"detail": f"Error creating checkout session: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(detail=False, methods=['post'], url_path='cancel')
    def cancel_subscription(self, request):
        """Cancel user's subscription"""
        user = request.user
        
        if not user.is_gastronom:
            return Response(
                {"detail": "Only Gastronom users can cancel subscriptions."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            subscription = Subscription.objects.get(gastronom=user)
            
            if subscription.stripe_subscription_id:
                stripe.Subscription.modify(
                    subscription.stripe_subscription_id,
                    cancel_at_period_end=True
                )
            
            subscription.status = Subscription.STATUS_CANCELLED
            subscription.save()
            
            return Response({
                "detail": "Subscription will be cancelled at the end of the billing period.",
                "subscription": SubscriptionSerializer(subscription).data
            })
            
        except Subscription.DoesNotExist:
            return Response(
                {"detail": "No active subscription found."},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"detail": f"Error cancelling subscription: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )


@api_view(['POST'])
@permission_classes([AllowAny])
def stripe_webhook(request):
    """Handle Stripe webhooks"""
    payload = request.body
    sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')
    
    logger.info("=" * 50)
    logger.info("Received Stripe webhook")
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, settings.STRIPE_WEBHOOK_SECRET
        )
        logger.info(f"✅ Webhook verified: {event['type']}")
    except ValueError as e:
        logger.error(f"❌ Invalid payload: {e}")
        return Response({"error": "Invalid payload"}, status=status.HTTP_400_BAD_REQUEST)
    except stripe.error.SignatureVerificationError as e:
        logger.error(f"❌ Invalid signature: {e}")
        return Response({"error": "Invalid signature"}, status=status.HTTP_400_BAD_REQUEST)
    
    # Handle different event types
    try:
        if event['type'] == 'checkout.session.completed':
            logger.info("Processing checkout.session.completed")
            session = event['data']['object']
            handle_checkout_session_completed(session)
        
        elif event['type'] == 'customer.subscription.created':
            logger.info("Processing customer.subscription.created")
            subscription = event['data']['object']
            handle_subscription_created(subscription)
        
        elif event['type'] == 'customer.subscription.updated':
            logger.info("Processing customer.subscription.updated")
            subscription = event['data']['object']
            handle_subscription_updated(subscription)
        
        elif event['type'] == 'customer.subscription.deleted':
            logger.info("Processing customer.subscription.deleted")
            subscription = event['data']['object']
            handle_subscription_deleted(subscription)
        
        elif event['type'] == 'invoice.payment_succeeded':
            logger.info("Processing invoice.payment_succeeded")
            invoice = event['data']['object']
            handle_payment_succeeded(invoice)
        
        elif event['type'] == 'invoice.payment_failed':
            logger.info("Processing invoice.payment_failed")
            invoice = event['data']['object']
            handle_payment_failed(invoice)
        
        else:
            logger.info(f"ℹ️  Unhandled event type: {event['type']}")
        
        logger.info("✅ Webhook processed successfully")
        return Response({"status": "success"}, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"❌ Error processing webhook: {str(e)}", exc_info=True)
        # Return 200 to prevent Stripe from retrying
        return Response({"status": "error", "message": str(e)}, status=status.HTTP_200_OK)


def handle_checkout_session_completed(session):
    try:
        logger.info(f"🔔 Checkout Session Completed: {session}")
        metadata = session.get("metadata", {})
        user_id = metadata.get("user_id")
        location_id = metadata.get("location_id")
        plan_type = metadata.get("plan_type", Subscription.PLAN_MONTHLY)

        if not user_id or not location_id:
            logger.error(f"❌ Missing metadata: user_id={user_id}, location_id={location_id}")
            return

        logger.info(f"🔍 Looking for subscription: user={user_id}, location={location_id}")

     
        try:
            subscription = Subscription.objects.get(
                gastronom_id=user_id,
                location_id=location_id
            )
        except Subscription.DoesNotExist:
            logger.error(f"❌ Subscription not found for user={user_id}, location={location_id}")
            return

       
        stripe_subscription_id = session.get("subscription")

        if not stripe_subscription_id:
            logger.error("❌ No Stripe subscription ID in session")
            return

        subscription.stripe_subscription_id = stripe_subscription_id

        try:
            stripe_sub = stripe.Subscription.retrieve(stripe_subscription_id)
            logger.info(f"☑ Retrieved Stripe subscription {stripe_subscription_id}")
        except Exception as e:
            logger.error(f"❌ Error fetching Stripe subscription: {e}", exc_info=True)
            return

   
        period_start = None
        period_end = None

        try:
            latest_invoice_id = stripe_sub.get("latest_invoice")
            logger.info(f"🧾 Latest invoice ID: {latest_invoice_id}")

            if latest_invoice_id:
                invoice = stripe.Invoice.retrieve(latest_invoice_id)
                line_item = invoice["lines"]["data"][0]

                period_start = line_item["period"]["start"]
                period_end = line_item["period"]["end"]

                logger.info(f"⏳ Period start/end: {period_start} / {period_end}")
            else:
                logger.warning("⚠ No latest_invoice found in Stripe subscription")

        except Exception as e:
            logger.error(f"❌ Error retrieving invoice period: {e}", exc_info=True)

     
        if period_start:
            subscription.current_period_start = datetime.fromtimestamp(
                period_start, tz=timezone.utc
            )
        if period_end:
            subscription.current_period_end = datetime.fromtimestamp(
                period_end, tz=timezone.utc
            )

      
        subscription.status = Subscription.STATUS_ACTIVE
        subscription.plan_type = plan_type
        subscription.save()

        logger.info(
            f"✅ Subscription updated → ID={subscription.id}, "
            f"Status=ACTIVE, Start={subscription.current_period_start}, End={subscription.current_period_end}"
        )

    except Exception as e:
        logger.error(f"❌ Error in handle_checkout_session_completed: {e}", exc_info=True)
        raise

def handle_subscription_created(stripe_subscription):
    """Handle new subscription creation"""
    try:
        subscription_id = stripe_subscription.get('id')
        customer_id = stripe_subscription.get('customer')
        
        logger.info(f"Subscription created: {subscription_id}, customer: {customer_id}")
        
        subscription = Subscription.objects.get(stripe_customer_id=customer_id)
        
        subscription.stripe_subscription_id = subscription_id
        
        # Map Stripe status to your model status
        stripe_status = stripe_subscription.get('status', 'incomplete')
        if stripe_status == 'active':
            subscription.status = Subscription.STATUS_ACTIVE
        elif stripe_status == 'past_due':
            subscription.status = Subscription.STATUS_PAST_DUE
        elif stripe_status == 'canceled':
            subscription.status = Subscription.STATUS_CANCELLED
        else:
            subscription.status = Subscription.STATUS_INACTIVE
        
        # Get period dates - Stripe might not include them in webhook, so retrieve full subscription
        try:
            full_sub = stripe.Subscription.retrieve(subscription_id)
            
            # Try to get current_period_start
            period_start = None
            if hasattr(full_sub, 'current_period_start'):
                period_start = full_sub.current_period_start
            elif 'current_period_start' in full_sub:
                period_start = full_sub['current_period_start']
            
            if period_start:
                subscription.current_period_start = datetime.fromtimestamp(
                    period_start,
                    tz=timezone.utc
                )
                logger.info(f"✅ Set period_start: {subscription.current_period_start}")
            
            # Try to get current_period_end
            period_end = None
            if hasattr(full_sub, 'current_period_end'):
                period_end = full_sub.current_period_end
            elif 'current_period_end' in full_sub:
                period_end = full_sub['current_period_end']
            
            if period_end:
                subscription.current_period_end = datetime.fromtimestamp(
                    period_end,
                    tz=timezone.utc
                )
                logger.info(f"✅ Set period_end: {subscription.current_period_end}")
                
        except Exception as retrieve_error:
            logger.error(f"Could not retrieve full subscription: {retrieve_error}")
        
        subscription.save()
        logger.info(f"✅ Subscription created in DB: {subscription.id}, status: {subscription.status}")
        
    except Subscription.DoesNotExist:
        logger.error(f"Subscription not found for customer: {customer_id}")
    except Exception as e:
        logger.error(f"Error in handle_subscription_created: {str(e)}", exc_info=True)
        raise


def handle_subscription_updated(stripe_subscription):
    """Handle subscription updates"""
    try:
        subscription_id = stripe_subscription.get('id') or stripe_subscription['id']
        logger.info(f"Updating subscription: {subscription_id}")
        
        subscription = Subscription.objects.get(
            stripe_subscription_id=subscription_id
        )
        
        # Map Stripe status to your model
        stripe_status = stripe_subscription.get('status', 'incomplete')
        if stripe_status == 'active':
            subscription.status = Subscription.STATUS_ACTIVE
        elif stripe_status == 'past_due':
            subscription.status = Subscription.STATUS_PAST_DUE
        elif stripe_status == 'canceled':
            subscription.status = Subscription.STATUS_CANCELLED
        elif stripe_status == 'incomplete':
            subscription.status = Subscription.STATUS_INACTIVE
        else:
            subscription.status = Subscription.STATUS_INACTIVE
        
        # Update period dates
        try:
            # Try to get from webhook data first
            period_start = None
            period_end = None
            
            if hasattr(stripe_subscription, 'current_period_start'):
                period_start = stripe_subscription.current_period_start
            elif 'current_period_start' in stripe_subscription:
                period_start = stripe_subscription['current_period_start']
            
            if hasattr(stripe_subscription, 'current_period_end'):
                period_end = stripe_subscription.current_period_end
            elif 'current_period_end' in stripe_subscription:
                period_end = stripe_subscription['current_period_end']
            
            # If not in webhook, retrieve full subscription
            if not period_start or not period_end:
                full_sub = stripe.Subscription.retrieve(subscription_id)
                if not period_start and hasattr(full_sub, 'current_period_start'):
                    period_start = full_sub.current_period_start
                if not period_end and hasattr(full_sub, 'current_period_end'):
                    period_end = full_sub.current_period_end
            
            if period_start:
                subscription.current_period_start = datetime.fromtimestamp(
                    period_start,
                    tz=timezone.utc
                )
            if period_end:
                subscription.current_period_end = datetime.fromtimestamp(
                    period_end,
                    tz=timezone.utc
                )
        except Exception as e:
            logger.warning(f"Could not update period dates: {e}")
        
        subscription.save()
        logger.info(f"✅ Subscription updated: {subscription.id}, status: {subscription.status}")
        
    except Subscription.DoesNotExist:
        logger.warning(f"Subscription not found for ID: {subscription_id}")
    except Exception as e:
        logger.error(f"Error in handle_subscription_updated: {str(e)}", exc_info=True)
        raise


def handle_subscription_deleted(stripe_subscription):
   
    try:
        subscription_id = stripe_subscription['id']
        logger.info(f"Deleting subscription: {subscription_id}")
        
        subscription = Subscription.objects.get(
            stripe_subscription_id=subscription_id
        )
        
        subscription.status = Subscription.STATUS_CANCELLED
        subscription.save()
        
        logger.info(f"✅ Subscription cancelled: {subscription.id}")
        
    except Subscription.DoesNotExist:
        logger.warning(f"Subscription not found for ID: {subscription_id}")
    except Exception as e:
        logger.error(f"Error in handle_subscription_deleted: {str(e)}", exc_info=True)
        raise


def handle_payment_succeeded(invoice):
 
    try:
      
        subscription_id = invoice.get('subscription')
        
        if not subscription_id and hasattr(invoice, 'subscription'):
            subscription_id = invoice.subscription
        
        if not subscription_id:
            logger.info("Invoice is not for a subscription (might be one-time payment)")
            return
        
        logger.info(f"Payment succeeded for subscription: {subscription_id}")
        
        subscription = Subscription.objects.get(
            stripe_subscription_id=subscription_id
        )
        
        subscription.status = Subscription.STATUS_ACTIVE
        subscription.save()
        
        logger.info(f"✅ Subscription activated after payment: {subscription.id}")
        
    except Subscription.DoesNotExist:
        logger.warning(f"Subscription not found for ID: {subscription_id}")
    except Exception as e:
        logger.error(f"Error in handle_payment_succeeded: {str(e)}", exc_info=True)
        raise


def handle_payment_failed(invoice):
    try:
        subscription_id = invoice.get('subscription')
        if not subscription_id:
            return
        
        subscription = Subscription.objects.get(
            stripe_subscription_id=subscription_id
        )
        subscription.status = Subscription.STATUS_PAST_DUE
        subscription.save()
        
    except Subscription.DoesNotExist:
        pass
    except Exception as e:
        raise

    try:
        subscription_id = invoice.get('subscription')
        
        if not subscription_id:
            logger.warning("No subscription ID in invoice")
            return
        
        logger.info(f"Payment failed for subscription: {subscription_id}")
        
        subscription = Subscription.objects.get(
            stripe_subscription_id=subscription_id
        )
        
        subscription.status = Subscription.STATUS_PAST_DUE
        subscription.save()
        
        logger.info(f"✅ Subscription marked as past due: {subscription.id}")
        
    except Subscription.DoesNotExist:
        logger.warning(f"Subscription not found for ID: {subscription_id}")
    except Exception as e:
        logger.error(f"Error in handle_payment_failed: {str(e)}", exc_info=True)
        raise
    """Handle failed payment"""
    try:
        subscription = Subscription.objects.get(
            stripe_subscription_id=invoice['subscription']
        )
        subscription.status = Subscription.STATUS_PAST_DUE
        subscription.save()
    except Subscription.DoesNotExist:
        pass