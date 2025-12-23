# telegram_auth/serializers.py
from rest_framework import serializers
from django.contrib.auth import get_user_model
from .services import TelegramAuthService

User = get_user_model()


class TelegramAuthSerializer(serializers.Serializer):
    """Сериализатор для аутентификации через Telegram Widget"""
    
    initData = serializers.CharField(required=False, write_only=True)
    
    id = serializers.IntegerField(required=False)
    first_name = serializers.CharField(required=False, allow_blank=True)
    last_name = serializers.CharField(required=False, allow_blank=True)
    username = serializers.CharField(required=False, allow_blank=True)
    photo_url = serializers.URLField(required=False, allow_blank=True)
    auth_date = serializers.IntegerField(required=False)
    hash = serializers.CharField(required=False)
    
    def validate(self, attrs):
        if 'initData' in attrs:
            init_data = attrs['initData']
            parsed_data = TelegramAuthService.parse_telegram_init_data(init_data)
            
            for key, value in parsed_data.items():
                if key not in attrs or not attrs[key]:
                    attrs[key] = value
        
        required_fields = ['id', 'auth_date', 'hash']
        for field in required_fields:
            if field not in attrs or not attrs[field]:
                raise serializers.ValidationError(
                    f"Поле {field} обязательно"
                )
        
        return attrs


class RefreshTokenSerializer(serializers.Serializer):
    """Сериализатор для обновления токена"""
    refresh = serializers.CharField(required=True)


class UserProfileSerializer(serializers.ModelSerializer):
    """Сериализатор для профиля пользователя"""
    class Meta:
        model = User
        fields = [
            'id',
            'telegram_id',
            'telegram_username',
            'telegram_first_name',
            'telegram_last_name',
            'telegram_photo_url',
            'date_joined',
            'last_login',
        ]