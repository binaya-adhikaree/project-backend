from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    register_view, login_view, logout_view, profile_view, profile_update_view, change_password_view,
    UserViewSet, LocationViewSet, LocationAccessViewSet,SubscriptionViewSet,stripe_webhook ,PasswordResetConfirmView,PasswordResetRequestView
)
from rest_framework_simplejwt.views import TokenRefreshView
from .views import DocumentUploadViewSet, FormSubmissionViewSet

router = DefaultRouter()
router.register(r'subscriptions', SubscriptionViewSet, basename='subscription')
router.register(r"users", UserViewSet, basename="user")
router.register(r"locations", LocationViewSet, basename="location")
router.register(r"location-access", LocationAccessViewSet, basename="locationaccess")
router.register(r'documents', DocumentUploadViewSet, basename='documents')
router.register(r'forms', FormSubmissionViewSet, basename='forms')



urlpatterns = [
    # Auth
    path("auth/register/", register_view, name="auth-register"),
    path("auth/login/", login_view, name="auth-login"),
    path("auth/logout/", logout_view, name="auth-logout"),
    path("auth/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    

     

    path('password-reset/', PasswordResetRequestView.as_view(), name='password-reset-request'),
    path('password-reset-confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
     
    #Profile
    path("auth/profile/", profile_view, name="auth-profile"),
    path("auth/profile/update/", profile_update_view, name="auth-profile-update"),


    # API viewsets
    path("", include(router.urls)),

    # payment
     path("webhooks/stripe/", stripe_webhook, name="stripe-webhook"),
]
