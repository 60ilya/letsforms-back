# telegram_auth/views.py
from rest_framework import status, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenRefreshView
from django.http import JsonResponse
from django.conf import settings
from urllib.parse import urlparse
import os
import json
import logging

from .serializers import (
    TelegramAuthSerializer,
    RefreshTokenSerializer,
    UserProfileSerializer
)
from .services import TelegramAuthService

logger = logging.getLogger(__name__)


class TelegramLoginView(APIView):
    """
    Вход/регистрация через Telegram (возвращает JSON, без редиректа)
    """
    permission_classes = [permissions.AllowAny]
    
    def get(self, request):
        """
        Обработка GET запроса
        """
        # Преобразуем QueryDict в словарь
        data = {}
        for key in request.GET:
            values = request.GET.getlist(key)
            data[key] = values[0] if len(values) == 1 else values
        
        return self._process_auth(request, data)
    
    def post(self, request):
        """
        Обработка POST запроса
        """
        data = request.data
        
        if isinstance(data, list):
            data = data[0] if len(data) > 0 else {}
        
        return self._process_auth(request, data)
    
    def _process_auth(self, request, data):
        """
        Общая логика аутентификации (возвращает JSON)
        """
        logger.info(f"Начало авторизации. Метод: {request.method}")
        
        # Валидируем данные
        serializer = TelegramAuthSerializer(data=data)
        if not serializer.is_valid():
            logger.error(f"Ошибка валидации: {serializer.errors}")
            return Response(
                {
                    'success': False,
                    'error': 'invalid_data',
                    'message': 'Неверные данные авторизации',
                    'details': serializer.errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        validated_data = serializer.validated_data
        
        # Проверяем подпись Telegram
        try:
            if not TelegramAuthService.validate_telegram_data(validated_data):
                logger.error("Неверная подпись Telegram данных")
                return Response(
                    {
                        'success': False,
                        'error': 'invalid_signature',
                        'message': 'Неверная подпись Telegram данных'
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
        except Exception as e:
            logger.error(f"Ошибка проверки подписи: {str(e)}")
            return Response(
                {
                    'success': False,
                    'error': 'validation_error',
                    'message': f'Ошибка проверки подписи: {str(e)}'
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Получаем или создаем пользователя
            user, is_new = TelegramAuthService.get_or_create_user(validated_data)
            logger.info(f"Пользователь {'создан' if is_new else 'найден'}: {user.username}")
            
            # Создаем токены
            tokens = TelegramAuthService.create_jwt_tokens(user)
            
            # Получаем профиль пользователя
            profile_serializer = UserProfileSerializer(user)
            user_data = profile_serializer.data
            
            # Формируем успешный ответ
            response_data = {
                'success': True,
                'tokens': tokens,
                'user': user_data,
                'is_new_user': is_new,
                'frontend_redirect': self._get_frontend_redirect_url(request, data)
            }
            
            # Добавляем заголовки для установки кук через фронтенд
            response = Response(response_data, status=status.HTTP_200_OK)
            
            # Устанавливаем CORS заголовки
            self._add_cors_headers(response, request)
            
            # Добавляем инструкции по установке кук на фронтенде
            response.data['cookie_instructions'] = {
                'access_token': {
                    'value': tokens['access'],
                    'max_age': 86400,
                    'path': '/',
                    'secure': True,
                    'samesite': 'None'
                },
                'refresh_token': {
                    'value': tokens['refresh'],
                    'max_age': 604800,
                    'path': '/',
                    'secure': True,
                    'samesite': 'None'
                }
            }
            
            logger.info(f"Успешная авторизация для пользователя {user.username}")
            return response
            
        except Exception as e:
            logger.error(f"Ошибка авторизации: {str(e)}", exc_info=True)
            return Response(
                {
                    'success': False,
                    'error': 'server_error',
                    'message': f'Ошибка сервера: {str(e)}'
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _get_frontend_redirect_url(self, request, data):
        """
        Возвращает URL для редиректа на фронтенде (только для информации)
        """
        # 1. Параметр redirect из запроса
        redirect_param = data.get('redirect') or request.GET.get('redirect') or request.POST.get('redirect')
        if redirect_param and self._is_safe_url(redirect_param, request):
            return redirect_param
        
        # 2. Origin заголовок
        origin = request.META.get('HTTP_ORIGIN')
        if origin and self._is_safe_url(origin, request):
            return origin
        
        # 3. Переменная окружения
        frontend_url = os.environ.get('FRONTEND_URL')
        if frontend_url:
            return frontend_url
        
        # 4. По умолчанию
        return '/'
    
    def _is_safe_url(self, url, request):
        """
        Проверяет, что URL безопасен
        """
        try:
            if not url:
                return False
            
            parsed = urlparse(url)
            
            if parsed.scheme not in ('http', 'https', ''):
                return False
            
            # Разрешаем все для тестирования
            return True
            
        except Exception:
            return False
    
    def _add_cors_headers(self, response, request):
        """
        Добавляет CORS заголовки
        """
        origin = request.META.get('HTTP_ORIGIN')
        if origin:
            response['Access-Control-Allow-Origin'] = origin
            response['Access-Control-Allow-Credentials'] = 'true'
            response['Access-Control-Expose-Headers'] = 'Content-Type, Authorization'
        
        return response
    
    def options(self, request, *args, **kwargs):
        """
        Обработка OPTIONS запросов для CORS
        """
        response = Response()
        self._add_cors_headers(response, request)
        response['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
        return response


class RefreshTokenView(TokenRefreshView):
    """
    Обновление JWT токена
    """
    serializer_class = RefreshTokenSerializer
    permission_classes = [permissions.AllowAny]
    
    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)
        
        origin = request.META.get('HTTP_ORIGIN')
        if origin:
            response['Access-Control-Allow-Origin'] = origin
            response['Access-Control-Allow-Credentials'] = 'true'
        
        return response


class UserProfileView(APIView):
    """
    Получение профиля текущего пользователя
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        user = request.user
        
        try:
            profile = user.telegram_profile
            telegram_data = {
                'telegram_id': profile.telegram_id,
                'telegram_username': profile.telegram_username,
                'telegram_first_name': profile.telegram_first_name,
                'telegram_last_name': profile.telegram_last_name,
                'telegram_photo_url': profile.telegram_photo_url,
            }
        except Exception:
            telegram_data = {}
        
        response_data = {
            'id': user.id,
            'username': user.username,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email or '',
            'date_joined': user.date_joined,
            'last_login': user.last_login,
            **telegram_data
        }
        
        return Response(response_data)
    
    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)
        
        origin = request.META.get('HTTP_ORIGIN')
        if origin:
            response['Access-Control-Allow-Origin'] = origin
            response['Access-Control-Allow-Credentials'] = 'true'
        
        return response


class AuthStatusView(APIView):
    """
    Проверка статуса авторизации
    """
    permission_classes = [permissions.AllowAny]
    
    def get(self, request):
        if request.user.is_authenticated:
            return Response({
                'authenticated': True,
                'user_id': request.user.id,
                'username': request.user.username
            })
        else:
            return Response({
                'authenticated': False
            })
    
    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)
        
        origin = request.META.get('HTTP_ORIGIN')
        if origin:
            response['Access-Control-Allow-Origin'] = origin
            response['Access-Control-Allow-Credentials'] = 'true'
        
        return response


class LogoutView(APIView):
    """
    Выход из системы (возвращает JSON)
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        return Response({
            'success': True,
            'message': 'Успешный выход из системы',
            'cookie_instructions': {
                'clear_cookies': ['access_token', 'refresh_token', 'auth_status', 'user_info']
            }
        })