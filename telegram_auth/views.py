"""
Универсальный endpoint для авторизации сайта и Telegram бота
"""
import logging
import time
from rest_framework import status, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenRefreshView

from .serializers import (
    TelegramAuthSerializer,
    RefreshTokenSerializer,
    UserProfileSerializer
)
from .services import TelegramAuthService

logger = logging.getLogger(__name__)


class UniversalAuthAPIView(APIView):
    """
    Универсальный API endpoint для авторизации:
    - Ваш сайт (не Telegram Web App)
    - Telegram бот
    Просто возвращает JWT токены
    """
    permission_classes = [permissions.AllowAny]
    
    def get(self, request):
        """
        Обработка GET запроса от Telegram Widget
        """
        # Конвертируем GET параметры
        data = {
            'id': request.GET.get('id'),
            'first_name': request.GET.get('first_name', ''),
            'last_name': request.GET.get('last_name', ''),
            'username': request.GET.get('username', ''),
            'photo_url': request.GET.get('photo_url', ''),
            'auth_date': request.GET.get('auth_date', int(time.time())),
            'hash': request.GET.get('hash', ''),
        }
        
        # Просто вызываем POST логику с этими данными
        request._full_data = data
        return self.post(request)
    
    def post(self, request):
        """
        Обработка POST запроса.
        Принимает: {'id': 123, 'first_name': 'Имя', 'username': 'user'}
        Возвращает: JWT токены
        """
        logger.info("🔐 УНИВЕРСАЛЬНАЯ АВТОРИЗАЦИЯ")
        
        # 1. Проверяем обязательные поля
        data = request.data
        
        if 'id' not in data:
            return Response({
                'success': False,
                'error': 'missing_id',
                'message': 'Отсутствует обязательное поле: id'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        telegram_id = data['id']
        
        try:
            # 2. Подготавливаем данные для сервиса
            auth_data = {
                'id': telegram_id,
                'first_name': data.get('first_name', ''),
                'last_name': data.get('last_name', ''),
                'username': data.get('username', ''),
                'auth_date': int(time.time()),
                'hash': 'universal_auth',  # Фиксированный хеш для универсальной авторизации
            }
            
            # 3. Создаем/получаем пользователя
            user, is_new = TelegramAuthService.get_or_create_user(auth_data)
            logger.info(f"Пользователь {'создан' if is_new else 'найден'}: {user.username}")
            
            # 4. Создаем JWT токены
            tokens = TelegramAuthService.create_jwt_tokens(user)
            
            # 5. Возвращаем токены
            return Response({
                'success': True,
                'tokens': {
                    'access': tokens['access'],
                    'refresh': tokens['refresh'],
                },
                'user_id': user.id,
                'username': user.username,
                'is_new_user': is_new,
                'timestamp': int(time.time())
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Ошибка авторизации: {str(e)}", exc_info=True)
            return Response({
                'success': False,
                'error': 'server_error',
                'message': f'Ошибка сервера: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RefreshTokenAPIView(TokenRefreshView):
    """
    Обновление JWT токена
    """
    serializer_class = RefreshTokenSerializer
    permission_classes = [permissions.AllowAny]
    
    def finalize_response(self, request, response, *args, **kwargs):
        """Добавляем CORS заголовки"""
        response = super().finalize_response(request, response, *args, **kwargs)
        origin = request.META.get('HTTP_ORIGIN')
        if origin:
            response['Access-Control-Allow-Origin'] = origin
            response['Access-Control-Allow-Credentials'] = 'true'
        return response


class UserProfileAPIView(APIView):
    """
    Получение профиля текущего пользователя по JWT токену
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        user = request.user
        
        try:
            serializer = UserProfileSerializer(user)
            return Response(serializer.data)
        except Exception:
            return Response({
                'id': user.id,
                'username': user.username,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email': user.email
            })
    
    def finalize_response(self, request, response, *args, **kwargs):
        """Добавляем CORS заголовки"""
        response = super().finalize_response(request, response, *args, **kwargs)
        origin = request.META.get('HTTP_ORIGIN')
        if origin:
            response['Access-Control-Allow-Origin'] = origin
            response['Access-Control-Allow-Credentials'] = 'true'
        return response


class LogoutAPIView(APIView):
    """
    Выход из системы
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        return Response({
            'success': True,
            'message': 'Успешный выход из системы',
        })