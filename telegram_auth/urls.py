from django.urls import path
from .views import (
    TelegramLoginAPIView,
    RefreshTokenAPIView,
    UserProfileAPIView,
    AuthStatusAPIView,
    LogoutAPIView,
    HealthCheckAPIView
)

urlpatterns = [
    # Основные endpoints
    path('login/', TelegramLoginAPIView.as_view(), name='telegram-login'),
    path('refresh/', RefreshTokenAPIView.as_view(), name='refresh-token'),
    path('profile/', UserProfileAPIView.as_view(), name='user-profile'),
    path('status/', AuthStatusAPIView.as_view(), name='auth-status'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('health/', HealthCheckAPIView.as_view(), name='health-check'),
    
    # Legacy поддержка (опционально)
    path('telegram/', TelegramLoginAPIView.as_view(), name='telegram-login-legacy'),
]