# telegram_auth/services.py
import hashlib
import hmac
import json
import time
from urllib.parse import parse_qs, unquote
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()


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
        
        # Парсим JSON поле user если оно есть
        if 'user' in result:
            try:
                result['user'] = json.loads(result['user'])
            except json.JSONDecodeError:
                pass
        
        return result
    
    @staticmethod
    def get_or_create_user(telegram_data: dict):
        """
        Получает или создает пользователя на основе данных Telegram
        """
        # Извлекаем user данные
        user_data = telegram_data.get('user') or {}
        
        # Если user в JSON формате, распаковываем
        if isinstance(user_data, str):
            try:
                user_data = json.loads(user_data)
            except json.JSONDecodeError:
                user_data = {'id': user_data}
        
        # Объединяем все данные
        if isinstance(user_data, dict):
            merged_data = {**telegram_data, **user_data}
        else:
            merged_data = telegram_data.copy()
            merged_data['id'] = user_data
        
        # Получаем telegram_id
        telegram_id = merged_data.get('id')
        if not telegram_id:
            raise ValueError("Telegram ID не найден в данных")
        
        # Ищем пользователя по telegram_id
        try:
            user = User.objects.get(telegram_id=telegram_id)
            is_new = False
            
            # Обновляем данные
            user.telegram_username = merged_data.get('username', user.telegram_username)
            user.telegram_first_name = merged_data.get('first_name', user.telegram_first_name)
            user.telegram_last_name = merged_data.get('last_name', user.telegram_last_name)
            user.telegram_photo_url = merged_data.get('photo_url', user.telegram_photo_url)
            user.telegram_data = merged_data
            user.save()
            
        except User.DoesNotExist:
            # Создаем нового пользователя
            username = merged_data.get('username', f"tg_{telegram_id}")
            
            user = User.objects.create(
                telegram_id=telegram_id,
                telegram_username=merged_data.get('username'),
                telegram_first_name=merged_data.get('first_name', ''),
                telegram_last_name=merged_data.get('last_name', ''),
                telegram_photo_url=merged_data.get('photo_url'),
                telegram_data=merged_data,
                username=username,
                first_name=merged_data.get('first_name', ''),
                last_name=merged_data.get('last_name', ''),
                is_active=True,
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