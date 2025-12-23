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
        Общая логика аутентификации БЕЗ передачи user_id в URL
        """
        serializer = TelegramAuthSerializer(data=data)
        if not serializer.is_valid():
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

            # Создаем редирект ответ
            response = HttpResponseRedirect(redirect_to)

            # Устанавливаем куки с токенами (ключевой момент!)
            self._set_auth_cookies(response, tokens, user, request)

            # Добавляем только безопасные параметры в URL
            new_redirect = self._add_safe_url_params(redirect_to, user, is_new)
            response['Location'] = new_redirect

            # Добавляем заголовки для CORS
            self._add_cors_headers(response, request)

            return response

        except Exception as e:
            error_params = urlencode({
                'auth_error': 'server_error',
                'message': str(e)
            })
            error_url = f"{redirect_to}?{error_params}"
            return HttpResponseRedirect(error_url)

    def _set_auth_cookies(self, response, tokens, user, request):
        """
        Устанавливает все необходимые куки для авторизации
        """
        # 1. JWT токены (httpOnly - недоступны из JS для безопасности)
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

        # 2. Только безопасные данные о пользователе для JS (без ID!)
        # Но лучше вообще убрать user_info из кук и получать через API
        response.set_cookie(
            'auth_status',
            'authenticated',  # Просто флаг, что пользователь авторизован
            secure=not settings.DEBUG and request.is_secure(),
            samesite='Lax',
            max_age=86400,
            path='/',
            domain=self._get_cookie_domain(request)
        )

    def _add_safe_url_params(self, redirect_to, user, is_new):
        """
        Добавляет только безопасные параметры в URL редиректа
        """
        parsed_redirect = urlparse(redirect_to)
        query_params = {}

        # Парсим существующие query параметры
        if parsed_redirect.query:
            from urllib.parse import parse_qs
            existing_params = parse_qs(parsed_redirect.query)
            # Убираем все старые auth параметры для чистоты
            for key in list(existing_params.keys()):
                if not key.startswith('auth_'):
                    query_params[key] = existing_params[key][0] if len(existing_params[key]) == 1 else existing_params[key]

        # Добавляем только общие флаги, без конкретных данных пользователя
        query_params['auth_success'] = 'true'
        query_params['is_new_user'] = str(is_new).lower()
        # НЕ добавляем user_id!
        # query_params['user_id'] = str(user.id)  # УДАЛИТЬ ЭТУ СТРОКУ!

        # Собираем новый URL
        new_redirect = urlunparse((
            parsed_redirect.scheme,
            parsed_redirect.netloc,
            parsed_redirect.path,
            parsed_redirect.params,
            urlencode(query_params),
            parsed_redirect.fragment
        ))

        return new_redirect
    
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
    Безопасно через JWT токен в httpOnly cookie
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        user = request.user
        
        # Получаем профиль Telegram
        try:
            profile = user.telegram_profile
            telegram_data = {
                'telegram_id': profile.telegram_id,
                'telegram_username': profile.telegram_username,
                'telegram_first_name': profile.telegram_first_name,
                'telegram_last_name': profile.telegram_last_name,
                'telegram_photo_url': profile.telegram_photo_url,
            }
        except:
            telegram_data = {}
        
        # Формируем безопасный ответ (не отправляем чувствительные данные)
        response_data = {
            'id': user.id,
            'username': user.username,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email if user.email else '',
            'date_joined': user.date_joined,
            'last_login': user.last_login,
            **telegram_data
        }
        
        return Response(response_data)
    
    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)
        
        # Добавляем CORS заголовки
        origin = request.META.get('HTTP_ORIGIN')
        if origin and self._is_safe_url(origin, request):
            response['Access-Control-Allow-Origin'] = origin
            response['Access-Control-Allow-Credentials'] = 'true'
        
        return response
    
    def _is_safe_url(self, url, request):
        """Проверка безопасности URL для CORS"""
        try:
            parsed = urlparse(url)
            allowed_hosts = [
                request.get_host(),
                *getattr(settings, 'ALLOWED_HOSTS', []),
                *getattr(settings, 'ALLOWED_REDIRECT_DOMAINS', [])
            ]
            return any(parsed.netloc == host or parsed.netloc.endswith(f'.{host}') for host in allowed_hosts)
        except:
            return False


class LogoutView(APIView):
    """
    Выход из системы
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        # Получаем URL для редиректа или используем текущий домен
        redirect_to = request.data.get('redirect', '/')
        
        # Создаем ответ с удалением кук
        response = HttpResponseRedirect(redirect_to)
        
        # Удаляем все auth куки
        cookies_to_delete = [
            'access_token',
            'refresh_token',
            'auth_status',
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