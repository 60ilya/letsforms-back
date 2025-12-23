from django.contrib import admin
from .models import TelegramUserProfile

@admin.register(TelegramUserProfile)
class TelegramUserProfileAdmin(admin.ModelAdmin):
    list_display = ('telegram_id', 'telegram_username', 'user', 'created_at', 'updated_at')
    search_fields = ('telegram_id', 'telegram_username', 'user__username', 'telegram_first_name', 'telegram_last_name')
    list_filter = ('created_at', 'updated_at')
    readonly_fields = ('created_at', 'updated_at')
    fieldsets = (
        ('Пользователь Django', {
            'fields': ('user',)
        }),
        ('Данные Telegram', {
            'fields': (
                'telegram_id',
                'telegram_username',
                'telegram_first_name',
                'telegram_last_name',
                'telegram_photo_url',
                'telegram_auth_date'
            )
        }),
        ('Техническая информация', {
            'fields': (
                'telegram_data',
                'created_at',
                'updated_at'
            ),
            'classes': ('collapse',)
        }),
    )