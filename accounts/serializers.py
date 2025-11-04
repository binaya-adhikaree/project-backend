from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.db import transaction
from .models import User, Location, LocationAccess
from django.contrib.auth import authenticate
from .models import DocumentUpload, FormSubmission



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
        """✅ Ensure email is unique"""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already in use.")
        return value

    def validate(self, data):
        # ✅ Check passwords match
        if data["password"] != data["password2"]:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        
        # ✅ Validate password strength
        validate_password(data["password"])
        
        # ✅ Validate EXTERNAL users have company_name
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
        user.save()  # ✅ This will now work because models.py is fixed
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

    class Meta:
        model = LocationAccess
        fields = ["id", "location", "location_detail", "external_user", "external_user_detail",
                  "granted_by", "granted_at", "is_active"]
        read_only_fields = ["id", "granted_by", "granted_at", "is_active"]

    def create(self, validated_data):
        request = self.context.get("request")
        if request and request.user.is_authenticated:
            validated_data["granted_by"] = request.user
        access, created = LocationAccess.objects.get_or_create(
            location=validated_data["location"],
            external_user=validated_data["external_user"],
            defaults={"granted_by": validated_data.get("granted_by")}
        )
        if not created and not access.is_active:
            access.is_active = True
            access.granted_by = validated_data.get("granted_by")
            access.save()
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

    class Meta:
        model = DocumentUpload
        fields = "__all__"
        read_only_fields = ["uploaded_at", "locked"]

    def create(self, validated_data):
        request = self.context.get("request")
        if request and hasattr(request, "user"):
            validated_data["uploaded_by"] = request.user
        return super().create(validated_data)


class FormSubmissionSerializer(serializers.ModelSerializer):
    submitted_by = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = FormSubmission
        fields = "__all__"
        read_only_fields = ["submitted_at", "locked"]

    def create(self, validated_data):
        request = self.context.get("request")
        if request and hasattr(request, "user"):
            validated_data["submitted_by"] = request.user
        return super().create(validated_data)



