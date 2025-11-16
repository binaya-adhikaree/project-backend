from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.db import transaction
from .models import User, Location, LocationAccess
from django.contrib.auth import authenticate
from .models import DocumentUpload, FormSubmission,Subscription

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            "id", "username", "email", "first_name", "last_name",
            "role", "phone", "company_name", "assigned_location",
            "is_active", "created_at", "updated_at",
        ]
        read_only_fields = ["id", "is_active", "created_at", "updated_at"]

class UserCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    password2 = serializers.CharField(write_only=True, required=True)
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES, required=False)

    class Meta:
        model = User
        fields = ["id", "username", "email", "password", "password2",
                  "first_name", "last_name", "role", "phone", "company_name"]
        read_only_fields = ["id"]

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already in use.")
        return value

    def validate(self, data):
       
        if data["password"] != data["password2"]:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        
        
        validate_password(data["password"])
        
        
        role = data.get("role", User.ROLE_GASTRONOM)
        if role == User.ROLE_EXTERNAL and not data.get("company_name"):
            raise serializers.ValidationError({
                "company_name": "Company name is required for EXTERNAL users."
            })
        
        return data

    def create(self, validated_data):
        validated_data.pop("password2", None)
        password = validated_data.pop("password")
        role = validated_data.get("role", None)
        if role is None:
            validated_data["role"] = User.ROLE_GASTRONOM

        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["email", "first_name", "last_name", "phone", "company_name"]

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    new_password2 = serializers.CharField(required=True)

    def validate(self, data):
        if data["new_password"] != data["new_password2"]:
            raise serializers.ValidationError({"new_password": "New passwords do not match."})
        validate_password(data["new_password"])
        return data

class LocationSerializer(serializers.ModelSerializer):
    current_operator = UserSerializer(read_only=True)
    current_operator_id = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.filter(role=User.ROLE_GASTRONOM),
        source="current_operator",
        write_only=True,
        required=False,
        allow_null=True
    )

    class Meta:
        model = Location
        fields = [
            "id", "name", "address", "city", "postal_code",
            "location_id", "current_operator", "current_operator_id",
            "is_active", "created_at", "updated_at"
        ]
        read_only_fields = ["id", "created_at", "updated_at", "current_operator"]

    def create(self, validated_data):
        validated_data.pop("current_operator", None)
        return super().create(validated_data)

class AssignOperatorSerializer(serializers.Serializer):
    operator_id = serializers.IntegerField()

    def validate_operator_id(self, value):
        try:
            user = User.objects.get(id=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("User not found.")
        if not user.is_gastronom:
            raise serializers.ValidationError("User is not a GASTRONOM.")
        return value

class LocationAccessSerializer(serializers.ModelSerializer):
    location_detail = LocationSerializer(source="location", read_only=True)
    external_user_detail = UserSerializer(source="external_user", read_only=True)
    granted_by_detail = UserSerializer(source="granted_by", read_only=True)

    class Meta:
        model = LocationAccess
        fields = [
            "id", 
            "location", "location_detail", 
            "external_user", "external_user_detail",
            "granted_by", "granted_by_detail",
            "granted_at", 
            "is_active"
        ]
        read_only_fields = ["id", "granted_by", "granted_at"]

    def validate_external_user(self, value):
      
        if value.role != User.ROLE_EXTERNAL:
            raise serializers.ValidationError("Access can only be granted to EXTERNAL users.")
        return value

    def validate(self, attrs):
      
        location = attrs.get('location')
        external_user = attrs.get('external_user')
        
        if not location:
            raise serializers.ValidationError({"location": "Location is required."})
        
        if not external_user:
            raise serializers.ValidationError({"external_user": "External user is required."})
        
       
        existing = LocationAccess.objects.filter(
            location=location,
            external_user=external_user
        ).first()
        
        if existing and existing.is_active:
            raise serializers.ValidationError(
                "This user already has active access to this location."
            )
        
        return attrs

    def create(self, validated_data):
   
        location = validated_data['location']
        external_user = validated_data['external_user']
        granted_by = validated_data.get('granted_by')

        
        existing_access = LocationAccess.objects.filter(
            location=location,
            external_user=external_user
        ).first()

        if existing_access:
            
            existing_access.is_active = True
            existing_access.granted_by = granted_by
            existing_access.save()
          
            return existing_access
        else:
            
            access = LocationAccess.objects.create(
                location=location,
                external_user=external_user,
                granted_by=granted_by,
                is_active=True
            )
            
            return access


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = authenticate(username=data["username"], password=data["password"])
        if not user:
            raise serializers.ValidationError("Invalid credentials.")
        if not user.is_active:
            raise serializers.ValidationError("User account is disabled.")
        data["user"] = user
        return data

class DocumentUploadSerializer(serializers.ModelSerializer):
    uploaded_by = serializers.StringRelatedField(read_only=True)
    uploaded_by_detail = UserSerializer(source='uploaded_by', read_only=True)
    location_detail = LocationSerializer(source='location', read_only=True)
    file_url = serializers.ReadOnlyField()
    file_name = serializers.ReadOnlyField()

    class Meta:
        model = DocumentUpload
        fields = [
            "id", 
            "location", 
            "location_detail", 
            "uploaded_by", 
            "uploaded_by_detail",
            "section", 
            "file", 
            "file_url", 
            "file_name", 
            "uploaded_at", 
            "locked", 
            "resource_type"
        ]
        read_only_fields = ["uploaded_at", "uploaded_by", "resource_type"]

    def create(self, validated_data):
        request = self.context.get("request")
        if request and hasattr(request, "user"):
            validated_data["uploaded_by"] = request.user
        return super().create(validated_data)

    def update(self, instance, validated_data):
        instance.section = validated_data.get("section", instance.section)
        file = validated_data.get("file", None)
        if file:
            instance.file = file
        instance.save()
        return instance

class FormSubmissionSerializer(serializers.ModelSerializer):
    submitted_by = UserSerializer(read_only=True)
    submitted_by_detail = UserSerializer(source='submitted_by', read_only=True)
    location_details = LocationSerializer(source='location', read_only=True)
    
    class Meta:
        model = FormSubmission
        fields = [
            'id', 'section', 'data', 'submitted_by', 'submitted_by_detail',
            'location', 'location_details', 'locked', 'submitted_at'
        ]
        read_only_fields = ['id', 'submitted_by', 'submitted_at']
    
    def create(self, validated_data):
        validated_data['submitted_by'] = self.context['request'].user
        return super().create(validated_data)
    
    def update(self, instance, validated_data):
        instance.data = validated_data.get('data', instance.data)
        instance.section = validated_data.get('section', instance.section)
        instance.locked = validated_data.get('locked', instance.locked)
        instance.save()
        return instance
    
class SubscriptionSerializer(serializers.ModelSerializer):
    gastronom_detail = UserSerializer(source='gastronom', read_only=True)
    location_detail = LocationSerializer(source='location', read_only=True)
    is_active = serializers.ReadOnlyField()
    can_upload = serializers.ReadOnlyField()

    class Meta:
        model = Subscription
        fields = [
            'id', 'gastronom', 'gastronom_detail', 'location', 'location_detail',
            'stripe_customer_id', 'stripe_subscription_id', 'plan_type', 'status',
            'current_period_start', 'current_period_end', 'is_active', 'can_upload',
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'stripe_customer_id', 'stripe_subscription_id', 'status',
            'current_period_start', 'current_period_end', 'created_at', 'updated_at'
        ]