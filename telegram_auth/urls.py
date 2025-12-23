# telegram_auth/urls.py
from django.urls import path
from . import views

urlpatterns = [
    # Основной эндпоинт для аутентификации (POST запрос)
    path('auth/telegram/', views.TelegramAuthView.as_view(), name='telegram-auth'),
    
    # Эндпоинт для редиректа от Telegram Widget (GET запрос)
    path('auth/telegram/callback/', views.TelegramAuthRedirectView.as_view(), name='telegram-auth-callback'),
    
    # Обновление токена
    path('auth/refresh/', views.CustomTokenRefreshView.as_view(), name='token-refresh'),
    
    # Выход
    path('auth/logout/', views.LogoutView.as_view(), name='logout'),
    
    # Профиль пользователя
    path('user/profile/', views.UserProfileView.as_view(), name='user-profile'),
]