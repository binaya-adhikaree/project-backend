from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from django.core.exceptions import ValidationError   
from cloudinary.utils import cloudinary_url
import cloudinary
from cloudinary.models import CloudinaryField
from django.conf import settings
import time

class User(AbstractUser):
    ROLE_ADMIN = "ADMIN"
    ROLE_GASTRONOM = "GASTRONOM"
    ROLE_EXTERNAL = "EXTERNAL"
    ROLE_CHOICES = [
        (ROLE_ADMIN, "Admin"),
        (ROLE_GASTRONOM, "Gastronom"),
        (ROLE_EXTERNAL, "External"),
    ]

    email = models.EmailField(unique=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default=ROLE_GASTRONOM)
    phone = models.CharField(max_length=30, blank=True, null=True)
    company_name = models.CharField(max_length=255, blank=True, null=True)
    assigned_location = models.ForeignKey("Location", on_delete=models.SET_NULL, null=True, blank=True, related_name="assigned_users")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    REQUIRED_FIELDS = ["email", "first_name", "last_name"]

    def clean(self):
        super().clean()
        if self.is_superuser:
            self.role = self.ROLE_ADMIN
        if self.role == self.ROLE_EXTERNAL and not self.company_name:
             raise ValidationError({"company_name": "company_name is required for EXTERNAL users."})

    @property
    def is_admin(self):
        return self.role == self.ROLE_ADMIN or self.is_staff or self.is_superuser

    @property
    def is_gastronom(self):
        return self.role == self.ROLE_GASTRONOM

    @property
    def is_external(self):
        return self.role == self.ROLE_EXTERNAL

    def __str__(self):
        return f"{self.username} ({self.role})"
    
    def save(self, *args, **kwargs):
      
        if self.is_superuser:
            self.role = self.ROLE_ADMIN
        super().save(*args, **kwargs) 


class Location(models.Model):
    name = models.CharField(max_length=255)
    address = models.TextField()
    city = models.CharField(max_length=100, default="Berlin")
    postal_code = models.CharField(max_length=20)
    location_id = models.CharField(max_length=100, unique=True)
   
    current_operator = models.OneToOneField("User", on_delete=models.SET_NULL, null=True, blank=True, related_name="current_operator_location")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    def change_operator(self, new_operator, changed_by=None):
        if new_operator is not None and not new_operator.is_gastronom:
            raise ValidationError("new_operator must be a GASTRONOM user.")
     
        old_operator = self.current_operator
        if old_operator:
            if old_operator.assigned_location and old_operator.assigned_location.id == self.id:
                old_operator.assigned_location = None
                old_operator.save(update_fields=["assigned_location", "updated_at"])
      
        if new_operator:
            new_operator.assigned_location = self
            new_operator.save(update_fields=["assigned_location", "updated_at"])
            self.current_operator = new_operator
        else:
            self.current_operator = None

        self.save(update_fields=["current_operator", "updated_at"])

    def __str__(self):
        return f"{self.name} ({self.location_id})"


class LocationAccess(models.Model):
    location = models.ForeignKey(Location, on_delete=models.CASCADE, related_name="access_grants")
    external_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="location_accesses")
    granted_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="granted_accesses")
    granted_at = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)

    class Meta:
        unique_together = ("location", "external_user")
        ordering = ["-granted_at"]

    def clean(self):
        if not self.external_user.is_external:
            raise ValidationError("external_user must have role EXTERNAL.")

    def __str__(self):
        status = "active" if self.is_active else "revoked"
        return f"Access: {self.external_user} -> {self.location} ({status})"

   
class DocumentUpload(models.Model):
    SECTION_CHOICES = [
        ("2.1", "Legal approvals and permits"),
        ("2.2", "Construction approval or safety certificate"),
        ("2.3", "Installation and operation manual"),
        ("2.4", "Maintenance certificate"),
        ("2.5", "Site plans and schematics"),
        ("3.5", "Waste removal record"),
        ("3.6", "Inspection report (General inspection)"),
        ("3.7", "Record of cleaning and detergents used"),
    ]

    location = models.ForeignKey("Location", on_delete=models.CASCADE, related_name="documents")
    uploaded_by = models.ForeignKey("User", on_delete=models.SET_NULL, null=True, related_name="uploaded_documents")
    section = models.CharField(max_length=10, choices=SECTION_CHOICES)
    
    file = CloudinaryField("file")  
    
    uploaded_at = models.DateTimeField(default=timezone.now)
    locked = models.BooleanField(default=True)
    resource_type = models.CharField(max_length=10, default="raw", choices=[("raw", "Raw"), ("image", "Image")])

    def __str__(self):
        return f"{self.location.name} - {self.section} ({self.uploaded_by.username})"

    @property
    def file_url(self):
        """Generate signed URL that works with authenticated Cloudinary accounts"""
        if not self.file:
            return None
        
        try:
            file_str = str(self.file)
            
            
            if '/upload/' in file_str:
                public_id = file_str.split('/upload/')[-1]
            else:
                public_id = file_str
            
            
            url, options = cloudinary_url(
                public_id,
                resource_type=self.resource_type,
                type="upload",
                sign_url=False, 
                secure=True     
            )
            
            return url
            
        except Exception as e:
            print(f"❌ Error generating file_url: {e}")
            return None
    
    @property
    def file_name(self):
        """Extract filename from Cloudinary public_id"""
        if not self.file:
            return None
            
        try:
            file_str = str(self.file)
            
            # Remove the /upload/ prefix if present
            if '/upload/' in file_str:
                file_str = file_str.split('/upload/')[-1]
           
            # Get the last part (filename)
            return file_str.split('/')[-1]
            
        except Exception as e:
            print(f"❌ Error getting file_name: {e}")
            return None


class FormSubmission(models.Model):
    SECTION_CHOICES = [
        ("3.1", "Proof of disposal, maintenance, and inspection"),
        ("3.2", "Disposal and self-inspection report"),
        ("3.3", "Maintenance report"),
        ("3.4", "Report of defects and repairs"),
    ]

    location = models.ForeignKey(Location, on_delete=models.CASCADE, related_name="forms")
    submitted_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name="form_submissions")
    section = models.CharField(max_length=10, choices=SECTION_CHOICES)
    data = models.JSONField()  # stores form fields dynamically
    submitted_at = models.DateTimeField(default=timezone.now)
    locked = models.BooleanField(default=True)  # no edits after submission

    def __str__(self):
        return f"{self.location.name} - {self.section} ({self.submitted_by.username})"


class Subscription(models.Model):
    PLAN_MONTHLY = "MONTHLY"
    PLAN_YEARLY = "YEARLY"
    PLAN_CHOICES = [
        (PLAN_MONTHLY, "Monthly"),
        (PLAN_YEARLY, "Yearly"),
    ]

    STATUS_ACTIVE = "ACTIVE"
    STATUS_INACTIVE = "INACTIVE"
    STATUS_CANCELLED = "CANCELLED"
    STATUS_PAST_DUE = "PAST_DUE"
    STATUS_CHOICES = [
        (STATUS_ACTIVE, "Active"),
        (STATUS_INACTIVE, "Inactive"),
        (STATUS_CANCELLED, "Cancelled"),
        (STATUS_PAST_DUE, "Past Due"),
    ]

    gastronom = models.OneToOneField(
        User, 
        on_delete=models.CASCADE, 
        related_name="subscription",
        limit_choices_to={'role': User.ROLE_GASTRONOM}
    )
    location = models.ForeignKey(
        Location, 
        on_delete=models.CASCADE, 
        related_name="subscriptions"
    )
    
   
    stripe_customer_id = models.CharField(max_length=255, blank=True, null=True)
    stripe_subscription_id = models.CharField(max_length=255, blank=True, null=True)
    
    #
    plan_type = models.CharField(max_length=20, choices=PLAN_CHOICES, default=PLAN_MONTHLY)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_INACTIVE)
    
   
    current_period_start = models.DateTimeField(null=True, blank=True)
    current_period_end = models.DateTimeField(null=True, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('gastronom', 'location')

    def __str__(self):
        return f"{self.gastronom.username} - {self.location.name} ({self.status})"

    @property
    def is_active(self):
        return self.status == self.STATUS_ACTIVE

    @property
    def can_upload(self):
        return self.is_active

    def clean(self):
        if self.gastronom and not self.gastronom.is_gastronom:
            raise ValidationError("Subscriptions can only be assigned to Gastronom users.")