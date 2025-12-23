# telegram_auth/views.py
from rest_framework import status, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenRefreshView
from django.shortcuts import redirect
from django.http import HttpResponseRedirect, JsonResponse
from django.conf import settings
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
import os
import json
import logging

from .serializers import (
    TelegramAuthSerializer,
    RefreshTokenSerializer,
    UserProfileSerializer
)
from .services import TelegramAuthService

# Логирование
logger = logging.getLogger(__name__)


class TelegramLoginView(APIView):
    """
    Вход/регистрация через Telegram с универсальным редиректом
    """
    permission_classes = [permissions.AllowAny]
    
    def get(self, request):
        """
        Обработка GET запроса
        """
        # Получаем данные из запроса
        data = dict(request.GET)
        for key, value in data.items():
            if isinstance(value, list) and len(value) == 1:
                data[key] = value[0]
        
        return self._process_auth(request, data)
    
    def post(self, request):
        """
        Обработка POST запроса
        """
        data = request.data.copy()
        if isinstance(data, list):
            data = data[0] if len(data) > 0 else {}
        
        return self._process_auth(request, data)
    
    def _process_auth(self, request, data):
        """
        Общая логика аутентификации
        """
        logger.info(f"Начало авторизации. Данные: {list(data.keys())}")
        
        serializer = TelegramAuthSerializer(data=data)
        if not serializer.is_valid():
            error_msg = f"Ошибка валидации: {serializer.errors}"
            logger.error(error_msg)
            return self._redirect_with_error(request, 'invalid_data', 'Неверные данные авторизации')
        
        validated_data = serializer.validated_data
        
        # Проверяем подпись Telegram
        try:
            if not TelegramAuthService.validate_telegram_data(validated_data):
                logger.error("Неверная подпись Telegram данных")
                return self._redirect_with_error(request, 'invalid_signature', 'Неверная подпись Telegram')
        except Exception as e:
            error_msg = f"Ошибка проверки подписи: {str(e)}"
            logger.error(error_msg)
            return self._redirect_with_error(request, 'validation_error', str(e))
        
        try:
            # Получаем или создаем пользователя
            user, is_new = TelegramAuthService.get_or_create_user(validated_data)
            logger.info(f"Пользователь {'создан' if is_new else 'найден'}: {user.username} (ID: {user.id})")
            
            # Создаем токены
            tokens = TelegramAuthService.create_jwt_tokens(user)
            
            # Определяем фронтенд домен для редиректа
            frontend_url = self._determine_frontend_url(request, data)
            logger.info(f"Фронтенд для редиректа: {frontend_url}")
            
            # Создаем редирект ответ на фронтенд
            response = HttpResponseRedirect(frontend_url)
            
            # Устанавливаем куки для фронтенда
            self._set_auth_cookies(response, tokens, user, request, frontend_url)
            
            # Добавляем параметры успеха в URL
            final_url = self._build_success_url(frontend_url, is_new, user.id)
            response['Location'] = final_url
            
            # Добавляем CORS заголовки
            self._add_cors_headers(response, request)
            
            logger.info(f"Успешная авторизация. Редирект на: {final_url}")
            return response
            
        except Exception as e:
            error_msg = f"Ошибка авторизации: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return self._redirect_with_error(request, 'server_error', str(e))
    
    def _determine_frontend_url(self, request, data):
        """
        Определяет URL фронтенда для редиректа
        Приоритеты:
        1. Параметр redirect из запроса
        2. Origin заголовок
        3. Переменная окружения FRONTEND_URL
        4. Текущий хост (фолбэк)
        """
        # 1. Параметр redirect из запроса (явное указание)
        redirect_param = data.get('redirect') or request.GET.get('redirect') or request.POST.get('redirect')
        if redirect_param and self._is_safe_url(redirect_param, request):
            return redirect_param.rstrip('/')
        
        # 2. Origin заголовок (для CORS запросов)
        origin = request.META.get('HTTP_ORIGIN')
        if origin and self._is_safe_url(origin, request):
            return origin.rstrip('/')
        
        # 3. Referer заголовок
        referer = request.META.get('HTTP_REFERER')
        if referer and self._is_safe_url(referer, request):
            parsed = urlparse(referer)
            return f"{parsed.scheme}://{parsed.netloc}"
        
        # 4. Переменная окружения FRONTEND_URL
        frontend_url = os.environ.get('FRONTEND_URL')
        if frontend_url:
            return frontend_url.rstrip('/')
        
        # 5. Переменная окружения FRONTEND_DOMAIN
        frontend_domain = os.environ.get('FRONTEND_DOMAIN')
        if frontend_domain:
            # Определяем протокол
            scheme = 'https' if request.is_secure() else 'http'
            return f"{scheme}://{frontend_domain}"
        
        # 6. Фолбэк: текущий хост
        scheme = 'https' if request.is_secure() else 'http'
        current_host = request.get_host()
        return f"{scheme}://{current_host}"
    
    def _is_safe_url(self, url, request):
        """
        Проверяет, что URL безопасен для редиректа
        """
        try:
            if not url:
                return False
            
            parsed = urlparse(url)
            
            # Проверяем схему
            if parsed.scheme not in ('http', 'https', ''):
                return False
            
            # Если нет домена - это относительный путь, безопасно
            if not parsed.netloc:
                return True
            
            # Получаем список разрешенных доменов
            allowed_hosts = [
                request.get_host(),
                *getattr(settings, 'ALLOWED_HOSTS', []),
                *self._get_allowed_domains_from_env(),
            ]
            
            # Проверяем, что домен в разрешенных
            for allowed_host in allowed_hosts:
                if not allowed_host:
                    continue
                
                # Сравниваем домены
                if parsed.netloc == allowed_host:
                    return True
                # Проверяем поддомены (например, .example.com)
                if allowed_host.startswith('.') and parsed.netloc.endswith(allowed_host):
                    return True
                # Проверяем wildcard
                if '*' in allowed_host:
                    pattern = allowed_host.replace('.', '\\.').replace('*', '.*')
                    import re
                    if re.match(pattern, parsed.netloc):
                        return True
            
            logger.warning(f"Домен {parsed.netloc} не в списке разрешенных")
            return False
            
        except Exception as e:
            logger.error(f"Ошибка проверки URL {url}: {str(e)}")
            return False
    
    def _get_allowed_domains_from_env(self):
        """
        Получает разрешенные домены из переменных окружения
        """
        domains = []
        
        # Из FRONTEND_URL
        frontend_url = os.environ.get('FRONTEND_URL')
        if frontend_url:
            parsed = urlparse(frontend_url)
            domains.append(parsed.netloc)
        
        # Из FRONTEND_DOMAIN
        frontend_domain = os.environ.get('FRONTEND_DOMAIN')
        if frontend_domain:
            domains.append(frontend_domain)
        
        # Из ALLOWED_REDIRECT_DOMAINS (через настройки)
        allowed_redirects = getattr(settings, 'ALLOWED_REDIRECT_DOMAINS', [])
        domains.extend(allowed_redirects)
        
        return domains
    
    def _set_auth_cookies(self, response, tokens, user, request, frontend_url):
        """
        Устанавливает куки авторизации для фронтенда
        """
        parsed = urlparse(frontend_url)
        frontend_domain = parsed.netloc
        
        # Определяем параметры кук
        is_local = 'localhost' in frontend_domain or '127.0.0.1' in frontend_domain
        cookie_domain = None if is_local else frontend_domain
        samesite_value = 'None' if not is_local else 'Lax'
        secure = not is_local or parsed.scheme == 'https'
        
        # Access Token (httpOnly для безопасности)
        response.set_cookie(
            key='access_token',
            value=tokens['access'],
            httponly=True,
            secure=secure,
            samesite=samesite_value,
            max_age=86400,  # 24 часа
            path='/',
            domain=cookie_domain,
        )
        
        # Refresh Token (httpOnly)
        response.set_cookie(
            key='refresh_token',
            value=tokens['refresh'],
            httponly=True,
            secure=secure,
            samesite=samesite_value,
            max_age=604800,  # 7 дней
            path='/',
            domain=cookie_domain,
        )
        
        # Флаг авторизации (для JS клиента)
        response.set_cookie(
            key='auth_status',
            value='authenticated',
            secure=secure,
            samesite=samesite_value,
            max_age=86400,
            path='/',
            domain=cookie_domain,
        )
        
        # Базовые данные пользователя (для JS)
        user_info = {
            'username': user.username,
            'first_name': user.first_name or '',
            'is_new': False,
        }
        
        response.set_cookie(
            key='user_info',
            value=json.dumps(user_info),
            secure=secure,
            samesite=samesite_value,
            max_age=86400,
            path='/',
            domain=cookie_domain,
        )
    
    def _build_success_url(self, frontend_url, is_new, user_id):
        """
        Собирает URL для успешного редиректа
        """
        parsed = urlparse(frontend_url)
        
        # Парсим существующие query параметры
        query_params = {}
        if parsed.query:
            existing_params = parse_qs(parsed.query)
            query_params = {k: v[0] if len(v) == 1 else v for k, v in existing_params.items()}
        
        # Добавляем наши параметры
        # ВАЖНО: user_id НЕ передаем в URL для безопасности!
        query_params['auth_success'] = 'true'
        query_params['is_new_user'] = str(is_new).lower()
        query_params['auth_timestamp'] = str(int(os.times().elapsed))
        
        # Собираем новый URL
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            urlencode(query_params),
            parsed.fragment
        ))
    
    def _redirect_with_error(self, request, error_type, message):
        """
        Редирект с ошибкой на фронтенд
        """
        try:
            # Определяем фронтенд для редиректа с ошибкой
            frontend_url = self._determine_frontend_url(request, {})
            
            # Кодируем сообщение об ошибке
            encoded_message = urlencode({'message': message})
            
            # Формируем URL с ошибкой
            error_params = urlencode({
                'auth_error': error_type,
                'message': message[:100]  # Ограничиваем длину
            })
            
            error_url = f"{frontend_url}?{error_params}"
            logger.info(f"Редирект с ошибкой на: {error_url}")
            
            return HttpResponseRedirect(error_url)
            
        except Exception as e:
            # Если даже редирект с ошибкой не работает, возвращаем JSON
            logger.error(f"Критическая ошибка редиректа: {str(e)}")
            return Response(
                {'error': 'Critical redirect error', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _add_cors_headers(self, response, request):
        """
        Добавляет CORS заголовки к ответу
        """
        origin = request.META.get('HTTP_ORIGIN')
        if origin and self._is_safe_url(origin, request):
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
            try:
                # Проверяем безопасность origin
                parsed = urlparse(origin)
                allowed_hosts = getattr(settings, 'ALLOWED_HOSTS', [])
                if parsed.netloc in [request.get_host(), *allowed_hosts]:
                    response['Access-Control-Allow-Origin'] = origin
                    response['Access-Control-Allow-Credentials'] = 'true'
            except Exception as e:
                logger.error(f"Ошибка CORS: {str(e)}")
        
        return response


class UserProfileView(APIView):
    """
    Получение профиля текущего пользователя
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
        except Exception as e:
            logger.warning(f"Telegram профиль не найден: {str(e)}")
            telegram_data = {}
        
        # Формируем безопасный ответ
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
        
        # Добавляем CORS заголовки
        origin = request.META.get('HTTP_ORIGIN')
        if origin:
            try:
                parsed = urlparse(origin)
                allowed_hosts = getattr(settings, 'ALLOWED_HOSTS', [])
                if parsed.netloc in [request.get_host(), *allowed_hosts]:
                    response['Access-Control-Allow-Origin'] = origin
                    response['Access-Control-Allow-Credentials'] = 'true'
            except Exception:
                pass
        
        return response


class LogoutView(APIView):
    """
    Выход из системы
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        # Получаем фронтенд для редиректа
        frontend_url = self._determine_frontend_url(request)
        
        # Создаем ответ с удалением кук
        response = HttpResponseRedirect(frontend_url)
        
        # Удаляем все auth куки
        cookies_to_delete = [
            'access_token',
            'refresh_token',
            'auth_status',
            'user_info',
            'sessionid',
            'csrftoken'
        ]
        
        for cookie in cookies_to_delete:
            response.delete_cookie(
                cookie,
                path='/',
                domain=self._get_cookie_domain(request, frontend_url)
            )
        
        return response
    
    def _determine_frontend_url(self, request):
        """
        Определяет URL фронтенда для редиректа после выхода
        """
        # Пытаемся получить из данных запроса
        redirect_to = request.data.get('redirect')
        if redirect_to:
            return redirect_to
        
        # Используем переменные окружения
        frontend_url = os.environ.get('FRONTEND_URL')
        if frontend_url:
            return frontend_url.rstrip('/')
        
        frontend_domain = os.environ.get('FRONTEND_DOMAIN')
        if frontend_domain:
            return f"https://{frontend_domain}"
        
        # Фолбэк
        return '/'
    
    def _get_cookie_domain(self, request, frontend_url):
        """
        Определяет домен для кук
        """
        parsed = urlparse(frontend_url)
        frontend_domain = parsed.netloc
        
        # Для localhost не задаем domain
        if 'localhost' in frontend_domain or '127.0.0.1' in frontend_domain:
            return None
        
        # Для остальных - домен без поддоменов для широких кук
        parts = frontend_domain.split('.')
        if len(parts) > 2:
            return f".{'.'.join(parts[-2:])}"
        
        return f".{frontend_domain}"


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