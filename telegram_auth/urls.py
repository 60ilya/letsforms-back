from django.urls import path
from .views import (
    TelegramLoginView,
    RefreshTokenView,
    UserProfileView
)

urlpatterns = [
    path('telegram-login/', TelegramLoginView.as_view(), name='telegram-login'),
    path('refresh-token/', RefreshTokenView.as_view(), name='refresh-token'),
    path('profile/', UserProfileView.as_view(), name='user-profile'),
]