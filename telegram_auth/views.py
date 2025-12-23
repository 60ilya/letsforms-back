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


class TelegramLoginView(APIView):
    """
    Вход/регистрация через Telegram
    Поддерживает как GET, так и POST запросы
    """
    permission_classes = [permissions.AllowAny]
    
    def get(self, request):
        """
        Обработка GET запроса с параметрами в query string
        """
        # Преобразуем QueryDict в обычный словарь
        data = dict(request.GET)
        
        # Если параметры пришли как списки, берем первый элемент
        for key, value in data.items():
            if isinstance(value, list) and len(value) == 1:
                data[key] = value[0]
        
        # Обрабатываем initData если он есть в GET параметрах
        if 'initData' in data:
            data['initData'] = data['initData']
        
        return self._process_auth(data)
    
    def post(self, request):
        """
        Обработка POST запроса с данными в body
        """
        data = request.data
        if isinstance(data, list):
            data = data[0] if len(data) > 0 else {}
        
        return self._process_auth(data)
    
    def _process_auth(self, data):
        """
        Общая логика аутентификации
        """
        serializer = TelegramAuthSerializer(data=data)
        if not serializer.is_valid():
            return Response(
                {'error': 'Неверные данные', 'details': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        validated_data = serializer.validated_data
        
        # Проверяем подпись Telegram
        try:
            if not TelegramAuthService.validate_telegram_data(validated_data):
                return Response(
                    {'error': 'Неверная подпись Telegram данных'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        except Exception as e:
            return Response(
                {'error': 'Ошибка проверки подписи', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        try:
            # Получаем или создаем пользователя
            user, is_new = TelegramAuthService.get_or_create_user(validated_data)
            
            # Создаем токены
            tokens = TelegramAuthService.create_jwt_tokens(user)
            
            # Получаем профиль пользователя
            profile_serializer = UserProfileSerializer(user)
            
            response_data = {
                'tokens': tokens,
                'user': profile_serializer.data,
                'is_new_user': is_new,
                'success': True
            }
            
            return Response(response_data, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response(
                {'error': 'Ошибка аутентификации', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class RefreshTokenView(TokenRefreshView):
    """
    Обновление JWT токена
    """
    serializer_class = RefreshTokenSerializer
    permission_classes = [permissions.AllowAny]


class UserProfileView(APIView):
    """
    Получение профиля текущего пользователя
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        user = request.user
        serializer = UserProfileSerializer(user)
        return Response(serializer.data)