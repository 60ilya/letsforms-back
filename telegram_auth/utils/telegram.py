"""
Утилиты для работы с Telegram Web App
"""
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


def extract_telegram_data_from_request(request) -> Optional[Dict[str, Any]]:
    """
    Извлекает данные Telegram из запроса фронтенда
    """
    try:
        data = request.data
        
        # Проверяем базовые поля
        if not data:
            logger.error("Получен пустой запрос")
            return None
        
        # Проверяем наличие обязательных полей
        required = ['id', 'auth_date', 'hash']
        for field in required:
            if field not in data:
                logger.error(f"Отсутствует обязательное поле: {field}")
                logger.error(f"Полученные поля: {list(data.keys())}")
                return None
        
        # Формируем чистый объект данных
        telegram_data = {
            'id': data['id'],
            'auth_date': data['auth_date'],
            'hash': data['hash'],
            'first_name': data.get('first_name', ''),
            'last_name': data.get('last_name', ''),
            'username': data.get('username', ''),
            'photo_url': data.get('photo_url', ''),
        }
        
        # Обрабатываем дополнительные поля
        if 'initData' in data and data['initData']:
            telegram_data['initData'] = data['initData']
        
        logger.info(f"Успешно извлечены данные Telegram для пользователя {telegram_data['id']}")
        return telegram_data
        
    except Exception as e:
        logger.error(f"Ошибка извлечения данных Telegram: {str(e)}")
        return None


def validate_telegram_request(request) -> Dict[str, Any]:
    """
    Валидирует запрос от фронтенда
    """
    result = {
        'valid': False,
        'error': None,
        'data': None
    }
    
    # Проверяем метод
    if request.method != 'POST':
        result['error'] = 'Метод должен быть POST'
        return result
    
    # Проверяем Content-Type
    content_type = request.content_type
    if content_type != 'application/json':
        result['error'] = f'Неподдерживаемый Content-Type: {content_type}. Ожидается application/json'
        return result
    
    # Извлекаем данные
    telegram_data = extract_telegram_data_from_request(request)
    
    if not telegram_data:
        result['error'] = 'Не удалось извлечь данные Telegram'
        return result
    
    result['valid'] = True
    result['data'] = telegram_data
    return result