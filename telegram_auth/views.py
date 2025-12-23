# telegram_auth/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.throttling import AnonRateThrottle
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

from .services import TelegramAuthService
from .serializers import TelegramAuthSerializer, UserProfileSerializer
from .models import TelegramUser


class TelegramAuthThrottle(AnonRateThrottle):
    """Rate limiting для аутентификации Telegram"""
    rate = '5/minute'  # 5 попыток в минуту



@method_decorator(csrf_exempt, name='dispatch')  # Отключаем CSRF для этого endpoint
class TelegramAuthView(APIView):
    """
    Аутентификация через Telegram Login Widget
    Поддерживает и GET (от виджета) и POST (от фронтенда)
    """
    permission_classes = [AllowAny]
    
    def get(self, request):
        """
        Обработка GET запроса от Telegram Widget
        Telegram отправляет параметры в query string:
        /api/auth/telegram/?id=...&hash=...&auth_date=...
        """
        # Получаем параметры из GET запроса
        telegram_data = request.GET.dict()
        
        if not telegram_data:
            return Response(
                {'error': 'No Telegram data provided'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        return self.process_telegram_auth(telegram_data)
    
    def post(self, request):
        """
        Обработка POST запроса от фронтенда
        Может содержать initData строку или отдельные параметры
        """
        # Если есть initData строка
        if 'initData' in request.data:
            init_data = request.data['initData']
            # Парсим initData строку в словарь
            from urllib.parse import parse_qs
            parsed = parse_qs(init_data)
            telegram_data = {k: v[0] for k, v in parsed.items() if v}
        else:
            # Или отдельные параметры
            telegram_data = request.data
        
        return self.process_telegram_auth(telegram_data)
    
    def process_telegram_auth(self, telegram_data):
        """
        Общая логика обработки аутентификации
        """
        try:
            # Проверяем подпись Telegram
            is_valid = TelegramAuthService.validate_telegram_data(telegram_data)
            
            if not is_valid:
                return Response(
                    {'error': 'Invalid Telegram signature'},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            # Получаем или создаем пользователя
            user, is_new = TelegramAuthService.get_or_create_user(telegram_data)
            
            # Создаем JWT токены
            tokens = TelegramAuthService.create_jwt_tokens(user)
            
            # Редирект на фронтенд или возвращаем JSON
            return Response({
                'success': True,
                'is_new_user': is_new,
                'user': {
                    'id': user.id,
                    'telegram_id': user.telegram_id,
                    'username': user.telegram_username,
                    'first_name': user.telegram_first_name,
                    'photo_url': user.telegram_photo_url,
                },
                'tokens': tokens
            })
            
        except ValueError as e:
            return Response(
                {'error': 'Validation error', 'message': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {'error': 'Server error', 'message': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class TelegramAuthRedirectView(APIView):
    """
    View для обработки редиректа от Telegram Widget
    Telegram Widget может перенаправлять пользователя с GET параметрами
    """
    permission_classes = [AllowAny]
    
    def get(self, request):
        # Получаем все GET параметры
        telegram_data = request.GET.dict()
        
        if not telegram_data:
            return Response(
                {'error': 'Нет данных для аутентификации'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Проверяем подпись
            is_valid = TelegramAuthService.validate_telegram_data(telegram_data)
            
            if not is_valid:
                return Response(
                    {'error': 'Недействительная подпись Telegram'},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            # Получаем или создаем пользователя
            user, is_new = TelegramAuthService.get_or_create_user(telegram_data)
            
            # Создаем JWT токены
            tokens = TelegramAuthService.create_jwt_tokens(user)
            
            # Здесь можно редиректить на фронтенд с токенами
            # Или возвращать JSON если это API запрос
            
            # Для API возвращаем JSON
            user_data = UserProfileSerializer(user).data
            
            return Response({
                'success': True,
                'is_new_user': is_new,
                'user': user_data,
                'tokens': tokens
            })
            
        except Exception as e:
            return Response(
                {'error': 'Ошибка аутентификации', 'message': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )


class LogoutView(APIView):
    """Выход из системы (помещает refresh токен в черный список)"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        try:
            refresh_token = request.data.get('refresh')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
            
            return Response({
                'success': True,
                'message': 'Успешный выход из системы'
            })
        except Exception as e:
            return Response(
                {'error': 'Не удалось выйти', 'message': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )


class UserProfileView(APIView):
    """Получение профиля текущего пользователя"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        serializer = UserProfileSerializer(user)
        return Response(serializer.data)


# Кастомный TokenRefreshView для обработки ошибок
class CustomTokenRefreshView(TokenRefreshView):
    """Кастомный view для обновления токена с обработкой ошибок"""
    def post(self, request, *args, **kwargs):
        try:
            return super().post(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {
                    'error': 'Не удалось обновить токен',
                    'message': str(e)
                },
                status=status.HTTP_400_BAD_REQUEST
            )