"""
Новые views для прямой работы с Telegram Web App
"""
import logging
from rest_framework import status, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenRefreshView
from django.http import JsonResponse
import time

from .serializers import (
    TelegramAuthSerializer,
    RefreshTokenSerializer,
    UserProfileSerializer,
    AuthStatusSerializer
)
from .services import TelegramAuthService
from .utils.telegram import validate_telegram_request

logger = logging.getLogger(__name__)


class TelegramLoginAPIView(APIView):
    """
    API endpoint для авторизации через Telegram Web App.
    Фронтенд получает данные от Telegram и отправляет их напрямую сюда.
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        """
        Обработка POST запроса с данными от Telegram Web App
        """
        logger.info("=" * 60)
        logger.info("📱 НОВЫЙ ЗАПРОС АВТОРИЗАЦИИ ЧЕРЕЗ TELEGRAM WEB APP")
        logger.info(f"Метод: {request.method}")
        logger.info(f"Content-Type: {request.content_type}")
        logger.info(f"IP: {request.META.get('REMOTE_ADDR')}")
        logger.info(f"User-Agent: {request.META.get('HTTP_USER_AGENT', 'Не указан')}")
        
        # 1. Валидация запроса
        validation_result = validate_telegram_request(request)
        if not validation_result['valid']:
            logger.error(f"❌ Ошибка валидации запроса: {validation_result['error']}")
            return Response({
                'success': False,
                'error': 'invalid_request',
                'message': validation_result['error'],
                'help': 'Отправьте JSON с полями id, auth_date, hash, полученными от Telegram Web App'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        telegram_data = validation_result['data']
        logger.info(f"✅ Данные Telegram валидированы. User ID: {telegram_data['id']}")
        
        # 2. Сериализация и дополнительная валидация
        serializer = TelegramAuthSerializer(data=telegram_data)
        if not serializer.is_valid():
            logger.error(f"❌ Ошибка сериализации: {serializer.errors}")
            return Response({
                'success': False,
                'error': 'validation_error',
                'message': 'Ошибка валидации данных',
                'details': serializer.errors,
                'received_data': telegram_data
            }, status=status.HTTP_400_BAD_REQUEST)
        
        validated_data = serializer.validated_data
        user_id = validated_data['id']
        logger.info(f"✅ Сериализация успешна. Проверяем подпись для пользователя {user_id}...")
        
        # 3. Проверка подписи Telegram
        try:
            is_valid = TelegramAuthService.validate_telegram_data(validated_data)
            if not is_valid:
                logger.error(f"❌ Неверная подпись Telegram для пользователя {user_id}")
                return Response({
                    'success': False,
                    'error': 'invalid_signature',
                    'message': 'Неверная подпись Telegram. Данные могли быть изменены.',
                    'user_id': user_id
                }, status=status.HTTP_400_BAD_REQUEST)
            
            logger.info(f"✅ Подпись Telegram проверена успешно")
            
        except Exception as e:
            logger.error(f"❌ Ошибка проверки подписи: {str(e)}")
            return Response({
                'success': False,
                'error': 'signature_check_failed',
                'message': f'Ошибка проверки подписи: {str(e)}',
                'user_id': user_id
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # 4. Создание/получение пользователя
        try:
            user, is_new = TelegramAuthService.get_or_create_user(validated_data)
            logger.info(f"✅ Пользователь {'создан' if is_new else 'найден'}: {user.username} (ID: {user.id})")
            
        except Exception as e:
            logger.error(f"❌ Ошибка создания/получения пользователя: {str(e)}", exc_info=True)
            return Response({
                'success': False,
                'error': 'user_creation_failed',
                'message': f'Ошибка создания пользователя: {str(e)}',
                'user_id': user_id
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        # 5. Создание JWT токенов
        try:
            tokens = TelegramAuthService.create_jwt_tokens(user)
            logger.info(f"✅ JWT токены созданы для пользователя {user.username}")
            
        except Exception as e:
            logger.error(f"❌ Ошибка создания токенов: {str(e)}")
            return Response({
                'success': False,
                'error': 'token_creation_failed',
                'message': f'Ошибка создания токенов: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        # 6. Получение данных профиля
        try:
            profile_serializer = UserProfileSerializer(user)
            user_data = profile_serializer.data
            logger.info(f"✅ Данные профиля получены")
            
        except Exception as e:
            logger.error(f"❌ Ошибка получения профиля: {str(e)}")
            # Все равно возвращаем успех, но без полного профиля
            user_data = {
                'id': user.id,
                'username': user.username,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'telegram_id': user_id
            }
        
        # 7. Формирование успешного ответа
        response_data = {
            'success': True,
            'message': 'Успешная регистрация' if is_new else 'Успешная авторизация',
            'is_new_user': is_new,
            'tokens': {
                'access': tokens['access'],
                'refresh': tokens['refresh'],
                'access_expires_in': 86400,  # 24 часа
                'refresh_expires_in': 604800,  # 7 дней
            },
            'user': user_data,
            'timestamp': validated_data['auth_date'],
            'cookie_instructions': self._get_cookie_instructions(tokens)
        }
        
        logger.info(f"🎉 АВТОРИЗАЦИЯ УСПЕШНА! Пользователь: {user.username}")
        logger.info("=" * 60)
        
        response = Response(response_data, status=status.HTTP_200_OK)
        self._add_cors_headers(response, request)
        
        return response
    
    def _get_cookie_instructions(self, tokens):
        """
        Возвращает инструкции для фронтенда по установке кук
        """
        return {
            'access_token': {
                'name': 'access_token',
                'value': tokens['access'],
                'options': {
                    'maxAge': 86400,  # 24 часа в секундах
                    'path': '/',
                    'secure': True,
                    'sameSite': 'None',  # Для кросс-доменных запросов
                    'httpOnly': False,   # Доступен для JS
                }
            },
            'refresh_token': {
                'name': 'refresh_token',
                'value': tokens['refresh'],
                'options': {
                    'maxAge': 604800,  # 7 дней в секундах
                    'path': '/',
                    'secure': True,
                    'sameSite': 'None',
                    'httpOnly': False,
                }
            }
        }
    
    def _add_cors_headers(self, response, request):
        """Добавляет CORS заголовки"""
        origin = request.META.get('HTTP_ORIGIN')
        if origin:
            response['Access-Control-Allow-Origin'] = origin
            response['Access-Control-Allow-Credentials'] = 'true'
            response['Access-Control-Expose-Headers'] = 'Content-Type, Authorization'
        
        return response
    
    def options(self, request, *args, **kwargs):
        """Обработка OPTIONS запросов для CORS"""
        response = Response()
        self._add_cors_headers(response, request)
        response['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        response['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
        response['Access-Control-Max-Age'] = '86400'
        return response


class RefreshTokenAPIView(TokenRefreshView):
    """
    Обновление JWT токена
    """
    serializer_class = RefreshTokenSerializer
    permission_classes = [permissions.AllowAny]
    
    def post(self, request, *args, **kwargs):
        logger.info("🔄 Запрос на обновление токена")
        return super().post(request, *args, **kwargs)
    
    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)
        
        # Добавляем CORS заголовки
        origin = request.META.get('HTTP_ORIGIN')
        if origin:
            response['Access-Control-Allow-Origin'] = origin
            response['Access-Control-Allow-Credentials'] = 'true'
        
        return response


class UserProfileAPIView(APIView):
    """
    Получение профиля текущего пользователя
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        user = request.user
        logger.info(f"📋 Запрос профиля пользователя {user.username}")
        
        try:
            profile_serializer = UserProfileSerializer(user)
            return Response(profile_serializer.data)
            
        except Exception as e:
            logger.error(f"Ошибка получения профиля: {str(e)}")
            return Response({
                'id': user.id,
                'username': user.username,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'error': 'profile_data_partial'
            })
    
    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)
        
        origin = request.META.get('HTTP_ORIGIN')
        if origin:
            response['Access-Control-Allow-Origin'] = origin
            response['Access-Control-Allow-Credentials'] = 'true'
        
        return response


class AuthStatusAPIView(APIView):
    """
    Проверка статуса авторизации
    """
    permission_classes = [permissions.AllowAny]
    
    def get(self, request):
        is_authenticated = request.user.is_authenticated
        
        if is_authenticated:
            data = {
                'authenticated': True,
                'user_id': request.user.id,
                'username': request.user.username,
                'first_name': request.user.first_name,
                'last_name': request.user.last_name,
            }
            logger.info(f"✅ Пользователь авторизован: {request.user.username}")
        else:
            data = {
                'authenticated': False,
                'message': 'Требуется авторизация'
            }
            logger.info("❌ Пользователь не авторизован")
        
        serializer = AuthStatusSerializer(data)
        return Response(serializer.data)
    
    def finalize_response(self, request, response, *args, **kwargs):
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
        user = request.user
        logger.info(f"🚪 Выход пользователя {user.username}")
        
        response_data = {
            'success': True,
            'message': 'Успешный выход из системы',
            'user_id': user.id,
            'username': user.username,
            'instructions': {
                'clear_local_storage': ['access_token', 'refresh_token', 'user_data'],
                'clear_cookies': ['access_token', 'refresh_token', 'auth_status'],
                'redirect_to': '/'
            }
        }
        
        return Response(response_data)
    
    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)
        
        origin = request.META.get('HTTP_ORIGIN')
        if origin:
            response['Access-Control-Allow-Origin'] = origin
            response['Access-Control-Allow-Credentials'] = 'true'
        
        return response


class HealthCheckAPIView(APIView):
    """
    Проверка здоровья API
    """
    permission_classes = [permissions.AllowAny]
    
    def get(self, request):
        return Response({
            'status': 'healthy',
            'service': 'telegram_auth',
            'timestamp': int(time.time()),
            'version': '1.0.0'
        })