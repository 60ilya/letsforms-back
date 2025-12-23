from rest_framework import status, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenRefreshView
from django.shortcuts import redirect
from django.http import HttpResponseRedirect, JsonResponse
from django.conf import settings
from urllib.parse import urlparse, urlencode, urlunparse
import json
import base64

from .serializers import (
    TelegramAuthSerializer,
    RefreshTokenSerializer,
    UserProfileSerializer
)
from .services import TelegramAuthService


class TelegramLoginView(APIView):
    """
    Вход/регистрация через Telegram с автоматическим редиректом на исходный домен
    """
    permission_classes = [permissions.AllowAny]
    
    def get(self, request):
        """
        Обработка GET запроса
        """
        # Получаем URL для редиректа (автоматически определяем)
        redirect_to = self._get_redirect_url(request)
        
        # Обрабатываем данные
        data = dict(request.GET)
        for key, value in data.items():
            if isinstance(value, list) and len(value) == 1:
                data[key] = value[0]
        
        return self._process_auth(request, data, redirect_to)
    
    def post(self, request):
        """
        Обработка POST запроса
        """
        # Получаем URL для редиректа
        redirect_to = self._get_redirect_url(request)
        
        data = request.data.copy()
        if isinstance(data, list):
            data = data[0] if len(data) > 0 else {}
        
        return self._process_auth(request, data, redirect_to)
    
    def _get_redirect_url(self, request):
        """
        Автоматически определяет URL для редиректа на основе источника запроса
        """
        # 1. Проверяем параметр redirect в запросе
        redirect_param = request.GET.get('redirect') or request.POST.get('redirect')
        if redirect_param:
            # Проверяем безопасность URL
            if self._is_safe_url(redirect_param, request):
                return redirect_param
        
        # 2. Проверяем referer (страница, с которой пришел пользователь)
        referer = request.META.get('HTTP_REFERER')
        if referer:
            if self._is_safe_url(referer, request):
                # Убираем query параметры из referer (чтобы не дублировать)
                parsed = urlparse(referer)
                clean_referer = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    '',  # params
                    '',  # query
                    ''   # fragment
                ))
                return clean_referer
        
        # 3. Проверяем origin (для CORS запросов)
        origin = request.META.get('HTTP_ORIGIN')
        if origin:
            if self._is_safe_url(origin, request):
                return origin
        
        # 4. Используем текущий домен с путем по умолчанию
        current_domain = request.build_absolute_uri('/')
        parsed = urlparse(current_domain)
        base_domain = f"{parsed.scheme}://{parsed.netloc}"
        
        # 5. Путь по умолчанию
        default_path = getattr(settings, 'DEFAULT_REDIRECT_PATH', '/')
        return f"{base_domain}{default_path}"
    
    def _is_safe_url(self, url, request):
        """
        Проверяет, что URL безопасен для редиректа
        """
        try:
            parsed = urlparse(url)
            
            # Пустой URL
            if not url:
                return False
            
            # Схема должна быть http или https
            if parsed.scheme not in ('http', 'https', ''):
                return False
            
            # Проверяем домен
            if parsed.netloc:
                # Получаем список разрешенных доменов
                allowed_hosts = [
                    request.get_host(),
                    *getattr(settings, 'ALLOWED_HOSTS', []),
                    *getattr(settings, 'ALLOWED_REDIRECT_DOMAINS', [])
                ]
                
                # Проверяем, что домен в списке разрешенных
                if not any(parsed.netloc == host or parsed.netloc.endswith(f'.{host}') for host in allowed_hosts):
                    return False
            
            return True
            
        except Exception:
            return False
    
    def _process_auth(self, request, data, redirect_to):
        """
        Общая логика аутентификации
        """
        serializer = TelegramAuthSerializer(data=data)
        if not serializer.is_valid():
            # Редирект с ошибкой
            error_params = urlencode({
                'auth_error': 'invalid_data',
                'message': 'Неверные данные авторизации'
            })
            error_url = f"{redirect_to}?{error_params}"
            return HttpResponseRedirect(error_url)
        
        validated_data = serializer.validated_data
        
        # Проверяем подпись Telegram
        try:
            if not TelegramAuthService.validate_telegram_data(validated_data):
                error_params = urlencode({
                    'auth_error': 'invalid_signature',
                    'message': 'Неверная подпись Telegram'
                })
                error_url = f"{redirect_to}?{error_params}"
                return HttpResponseRedirect(error_url)
        except Exception as e:
            error_params = urlencode({
                'auth_error': 'validation_error',
                'message': str(e)
            })
            error_url = f"{redirect_to}?{error_params}"
            return HttpResponseRedirect(error_url)
        
        try:
            # Получаем или создаем пользователя
            user, is_new = TelegramAuthService.get_or_create_user(validated_data)
            
            # Создаем токены
            tokens = TelegramAuthService.create_jwt_tokens(user)
            
            # Получаем профиль пользователя
            profile_serializer = UserProfileSerializer(user)
            user_data = profile_serializer.data
            
            # Создаем редирект ответ
            response = HttpResponseRedirect(redirect_to)
            
            # 1. Устанавливаем JWT токены в куки (httpOnly для безопасности)
            response.set_cookie(
                'access_token',
                tokens['access'],
                httponly=True,
                secure=not settings.DEBUG and request.is_secure(),
                samesite='Lax',
                max_age=86400,  # 24 часа
                path='/',
                domain=self._get_cookie_domain(request)
            )
            
            response.set_cookie(
                'refresh_token',
                tokens['refresh'],
                httponly=True,
                secure=not settings.DEBUG and request.is_secure(),
                samesite='Lax',
                max_age=604800,  # 7 дней
                path='/',
                domain=self._get_cookie_domain(request)
            )
            
            # 2. Куки с основной информацией о пользователе (доступно из JS)
            response.set_cookie(
                'user_info',
                json.dumps({
                    'id': user.id,
                    'username': user.username,
                    'first_name': user.first_name,
                    'is_new_user': is_new,
                    'telegram_id': user_data.get('telegram_id'),
                    'telegram_username': user_data.get('telegram_username')
                }),
                secure=not settings.DEBUG and request.is_secure(),
                samesite='Lax',
                max_age=86400,
                path='/',
                domain=self._get_cookie_domain(request)
            )
            
            # 3. Добавляем параметры в URL для случаев, когда куки не работают
            parsed_redirect = urlparse(redirect_to)
            query_params = {}
            
            # Парсим существующие query параметры
            if parsed_redirect.query:
                from urllib.parse import parse_qs
                query_params = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed_redirect.query).items()}
            
            # Добавляем флаг успешной авторизации
            query_params['auth_success'] = 'true'
            query_params['is_new_user'] = str(is_new).lower()
            query_params['user_id'] = str(user.id)
            
            # Собираем новый URL
            new_redirect = urlunparse((
                parsed_redirect.scheme,
                parsed_redirect.netloc,
                parsed_redirect.path,
                parsed_redirect.params,
                urlencode(query_params),
                parsed_redirect.fragment
            ))
            
            # Обновляем URL редиректа
            response['Location'] = new_redirect
            
            # 4. Добавляем заголовки для CORS
            origin = request.META.get('HTTP_ORIGIN')
            if origin and self._is_safe_url(origin, request):
                response['Access-Control-Allow-Origin'] = origin
                response['Access-Control-Allow-Credentials'] = 'true'
            
            return response
            
        except Exception as e:
            error_params = urlencode({
                'auth_error': 'server_error',
                'message': str(e)
            })
            error_url = f"{redirect_to}?{error_params}"
            return HttpResponseRedirect(error_url)
    
    def _get_cookie_domain(self, request):
        """
        Определяет домен для кук
        """
        # Для production используем основной домен
        host = request.get_host()
        
        # Убираем порт
        if ':' in host:
            host = host.split(':')[0]
        
        # Для localhost не задаем domain
        if host in ['localhost', '127.0.0.1']:
            return None
        
        # Для поддоменов используем основной домен
        parts = host.split('.')
        if len(parts) > 2:
            return f".{'.'.join(parts[-2:])}"
        
        return f".{host}"
    
    def options(self, request, *args, **kwargs):
        """
        Обработка OPTIONS запросов для CORS
        """
        response = Response()
        
        # Разрешаем запросы с любого безопасного origin
        origin = request.META.get('HTTP_ORIGIN')
        if origin and self._is_safe_url(origin, request):
            response['Access-Control-Allow-Origin'] = origin
            response['Access-Control-Allow-Credentials'] = 'true'
        
        response['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
        response['Access-Control-Max-Age'] = '86400'
        
        return response


class RefreshTokenView(TokenRefreshView):
    """
    Обновление JWT токена
    """
    serializer_class = RefreshTokenSerializer
    permission_classes = [permissions.AllowAny]
    
    def finalize_response(self, request, response, *args, **kwargs):
        """
        Добавляем CORS заголовки к ответу
        """
        response = super().finalize_response(request, response, *args, **kwargs)
        
        origin = request.META.get('HTTP_ORIGIN')
        if origin:
            # Проверяем безопасность origin
            try:
                parsed = urlparse(origin)
                if parsed.netloc in [request.get_host(), *getattr(settings, 'ALLOWED_HOSTS', [])]:
                    response['Access-Control-Allow-Origin'] = origin
                    response['Access-Control-Allow-Credentials'] = 'true'
            except:
                pass
        
        return response


class UserProfileView(APIView):
    """
    Получение профиля текущего пользователя
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        user = request.user
        serializer = UserProfileSerializer(user)
        return Response(serializer.data)
    
    def finalize_response(self, request, response, *args, **kwargs):
        """
        Добавляем CORS заголовки к ответу
        """
        response = super().finalize_response(request, response, *args, **kwargs)
        
        origin = request.META.get('HTTP_ORIGIN')
        if origin:
            try:
                parsed = urlparse(origin)
                if parsed.netloc in [request.get_host(), *getattr(settings, 'ALLOWED_HOSTS', [])]:
                    response['Access-Control-Allow-Origin'] = origin
                    response['Access-Control-Allow-Credentials'] = 'true'
            except:
                pass
        
        return response


class LogoutView(APIView):
    """
    Выход из системы
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        # Получаем URL для редиректа
        redirect_to = request.data.get('redirect', '/')
        
        # Создаем ответ с удалением кук
        response = HttpResponseRedirect(redirect_to)
        
        # Удаляем все auth куки
        cookies_to_delete = [
            'access_token',
            'refresh_token',
            'user_info',
            'sessionid',
            'csrftoken'
        ]
        
        for cookie in cookies_to_delete:
            response.delete_cookie(
                cookie,
                path='/',
                domain=self._get_cookie_domain(request)
            )
        
        return response
    
    def _get_cookie_domain(self, request):
        """
        Определяет домен для кук (аналогично методу в TelegramLoginView)
        """
        host = request.get_host()
        if ':' in host:
            host = host.split(':')[0]
        
        if host in ['localhost', '127.0.0.1']:
            return None
        
        parts = host.split('.')
        if len(parts) > 2:
            return f".{'.'.join(parts[-2:])}"
        
        return f".{host}"