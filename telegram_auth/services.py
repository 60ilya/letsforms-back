import hashlib
import hmac
import json
import time
from urllib.parse import parse_qs, unquote
from django.conf import settings
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone

from .models import TelegramUserProfile


class TelegramAuthService:
    """
    Сервис для проверки данных Telegram Login Widget
    """
    
    @staticmethod
    def validate_telegram_data(telegram_data: dict) -> bool:
        """
        Проверяет подпись данных Telegram
        """
        received_hash = telegram_data.get('hash')
        if not received_hash:
            return False
        
        # Создаем копию данных без hash
        data_copy = telegram_data.copy()
        data_copy.pop('hash', None)
        
        # Создаем data-check-string (ключи в алфавитном порядке)
        data_check_items = []
        for key in sorted(data_copy.keys()):
            if data_copy[key]:
                data_check_items.append(f"{key}={data_copy[key]}")
        
        data_check_string = "\n".join(data_check_items)
        
        # Секретный ключ = SHA256(bot_token)
        bot_token = settings.TELEGRAM_BOT_TOKEN
        if not bot_token:
            raise ValueError("TELEGRAM_BOT_TOKEN не настроен")
        
        secret_key = hashlib.sha256(bot_token.encode()).digest()
        
        # Вычисляем HMAC-SHA256
        calculated_hash = hmac.new(
            secret_key,
            data_check_string.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Сравниваем хеши
        if calculated_hash != received_hash:
            return False
        
        # Проверяем свежесть данных (не старше 24 часов)
        auth_date = telegram_data.get('auth_date')
        if auth_date:
            try:
                auth_timestamp = int(auth_date)
                current_timestamp = int(time.time())
                if current_timestamp - auth_timestamp > 86400:  # 24 часа
                    return False
            except (ValueError, TypeError):
                return False
        
        return True
    
    @staticmethod
    def parse_telegram_init_data(init_data_string: str) -> dict:
        """
        Парсит строку initData от Telegram Widget
        """
        parsed = parse_qs(init_data_string)
        
        result = {}
        for key, value in parsed.items():
            if value and len(value) == 1:
                result[key] = unquote(value[0])
        
        if 'user' in result:
            try:
                user_data = json.loads(result['user'])
                # Распаковываем пользовательские данные в корневой словарь
                if isinstance(user_data, dict):
                    for user_key, user_value in user_data.items():
                        result[user_key] = user_value
                result.pop('user', None)
            except json.JSONDecodeError:
                pass
        
        return result
    
    @staticmethod
    def get_or_create_user(telegram_data: dict):
        """
        Получает или создает пользователя на основе данных Telegram
        Работает со стандартной моделью User и профилем TelegramUserProfile
        """
        # Извлекаем основные данные
        telegram_id = telegram_data.get('id')
        if not telegram_id:
            raise ValueError("Telegram ID не найден в данных")
        
        # Подготавливаем данные, заменяем None на пустые строки
        first_name = telegram_data.get('first_name', '') or ''
        last_name = telegram_data.get('last_name', '') or ''  # Гарантируем строку
        username = telegram_data.get('username', f"tg_{telegram_id}") or f"tg_{telegram_id}"
        photo_url = telegram_data.get('photo_url', '') or ''
        
        # Ищем Telegram профиль
        try:
            profile = TelegramUserProfile.objects.get(telegram_id=telegram_id)
            user = profile.user
            is_new = False
            
            # Обновляем профиль
            profile.telegram_username = username
            profile.telegram_first_name = first_name
            profile.telegram_last_name = last_name
            if photo_url:
                profile.telegram_photo_url = photo_url
            profile.telegram_data = telegram_data
            profile.telegram_auth_date = timezone.now()
            profile.save()
            
            # Обновляем данные User (только если данные не пустые или не указаны)
            if first_name:
                user.first_name = first_name
            if last_name:
                user.last_name = last_name
            
            # Проверяем уникальность username
            if username and username != user.username:
                # Если username уже занят другим пользователем
                if User.objects.filter(username=username).exclude(id=user.id).exists():
                    # Генерируем уникальный username
                    counter = 1
                    base_username = username
                    while User.objects.filter(username=username).exclude(id=user.id).exists():
                        username = f"{base_username}_{counter}"
                        counter += 1
                user.username = username
            user.save()
            
        except TelegramUserProfile.DoesNotExist:
            # Создаем Django пользователя
            # Проверяем уникальность username
            base_username = username
            counter = 1
            
            while User.objects.filter(username=username).exists():
                username = f"{base_username}_{counter}"
                counter += 1
            
            # Создаем пользователя с гарантированно строковыми значениями
            user = User.objects.create_user(
                username=username,
                first_name=first_name,  # Уже гарантированно строка
                last_name=last_name,     # Уже гарантированно строка
                is_active=True
            )
            
            # Создаем Telegram профиль
            profile = TelegramUserProfile.objects.create(
                user=user,
                telegram_id=telegram_id,
                telegram_username=telegram_data.get('username', ''),
                telegram_first_name=first_name,
                telegram_last_name=last_name,
                telegram_photo_url=photo_url,
                telegram_auth_date=timezone.now(),
                telegram_data=telegram_data
            )
            is_new = True
        
        return user, is_new
    
    @staticmethod
    def create_jwt_tokens(user):
        """
        Создает JWT токены для пользователя
        """
        refresh = RefreshToken.for_user(user)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }