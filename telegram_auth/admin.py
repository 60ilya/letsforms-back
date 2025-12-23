# telegram_auth/admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import TelegramUser


@admin.register(TelegramUser)
class TelegramUserAdmin(UserAdmin):
    """Админ-панель для TelegramUser"""
    
    list_display = (
        'telegram_id',
        'telegram_username',
        'telegram_first_name',
        'telegram_last_name',
        'is_active',
        'is_staff',
        'date_joined',
    )
    
    list_filter = (
        'is_active',
        'is_staff',
        'is_superuser',
        'date_joined',
    )
    
    search_fields = (
        'telegram_id',
        'telegram_username',
        'telegram_first_name',
        'telegram_last_name',
        'email',
    )
    
    ordering = ('-date_joined',)
    
    fieldsets = (
        (None, {'fields': ('telegram_id', 'password')}),
        ('Telegram Info', {
            'fields': (
                'telegram_username',
                'telegram_first_name',
                'telegram_last_name',
                'telegram_photo_url',
                'telegram_auth_date',
                'telegram_data',
            )
        }),
        ('Permissions', {
            'fields': (
                'is_active',
                'is_staff',
                'is_superuser',
                'groups',
                'user_permissions',
            )
        }),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('telegram_id', 'password1', 'password2'),
        }),
    )