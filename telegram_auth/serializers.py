"""
Упрощенные сериализаторы для новой логики
"""
from rest_framework import serializers
from django.contrib.auth import get_user_model

User = get_user_model()


class TelegramAuthSerializer(serializers.Serializer):
    """
    Упрощенный сериализатор для Telegram аутентификации.
    Фронтенд сам получает данные от Telegram и отправляет их напрямую.
    """
    id = serializers.IntegerField(required=True)
    first_name = serializers.CharField(required=False, allow_blank=True)
    last_name = serializers.CharField(required=False, allow_blank=True)
    username = serializers.CharField(required=False, allow_blank=True)
    photo_url = serializers.URLField(required=False, allow_blank=True)
    auth_date = serializers.IntegerField(required=True)
    hash = serializers.CharField(required=True)
    initData = serializers.CharField(required=False, allow_blank=True)
    
    def validate(self, attrs):
        # Проверяем, что ID положительный
        if attrs['id'] <= 0:
            raise serializers.ValidationError({
                'id': 'ID пользователя должен быть положительным числом'
            })
        
        # Проверяем auth_date (не старше 24 часов)
        import time
        current_time = int(time.time())
        auth_age = current_time - attrs['auth_date']
        
        if auth_age > 86400:  # 24 часа
            raise serializers.ValidationError({
                'auth_date': 'Данные авторизации устарели (больше 24 часов)'
            })
        
        return attrs


class UserProfileSerializer(serializers.ModelSerializer):
    """Сериализатор профиля пользователя"""
    telegram_id = serializers.IntegerField(source='telegram_profile.telegram_id', read_only=True)
    telegram_username = serializers.CharField(source='telegram_profile.telegram_username', read_only=True)
    telegram_first_name = serializers.CharField(source='telegram_profile.telegram_first_name', read_only=True)
    telegram_last_name = serializers.CharField(source='telegram_profile.telegram_last_name', read_only=True)
    telegram_photo_url = serializers.URLField(source='telegram_profile.telegram_photo_url', read_only=True)
    
    class Meta:
        model = User
        fields = [
            'id',
            'username',
            'first_name',
            'last_name',
            'email',
            'date_joined',
            'last_login',
            'telegram_id',
            'telegram_username',
            'telegram_first_name',
            'telegram_last_name',
            'telegram_photo_url',
        ]
        read_only_fields = fields


class RefreshTokenSerializer(serializers.Serializer):
    """Сериализатор для обновления токена"""
    refresh = serializers.CharField(required=True)


class AuthStatusSerializer(serializers.Serializer):
    """Сериализатор статуса авторизации"""
    authenticated = serializers.BooleanField()
    user_id = serializers.IntegerField(required=False)
    username = serializers.CharField(required=False, allow_blank=True)