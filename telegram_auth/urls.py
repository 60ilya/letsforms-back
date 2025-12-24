from django.urls import path
from .views import (
    UniversalAuthAPIView,  # Универсальный эндпоинт
    RefreshTokenAPIView,
    UserProfileAPIView,
    LogoutAPIView
)

urlpatterns = [
    # Универсальный эндпоинт для сайта и бота
    path('auth/', UniversalAuthAPIView.as_view(), name='universal-auth'),
    
    # Legacy поддержка (если нужно)
    path('login/', UniversalAuthAPIView.as_view(), name='login'),
    path('telegram/', UniversalAuthAPIView.as_view(), name='telegram-auth'),
    
    # Другие эндпоинты
    path('auth/refresh/', RefreshTokenAPIView.as_view(), name='refresh-token'),
    path('auth/profile/', UserProfileAPIView.as_view(), name='user-profile'),
    path('auth/logout/', LogoutAPIView.as_view(), name='logout'),
]