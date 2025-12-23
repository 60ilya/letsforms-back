from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class TelegramUserProfile(models.Model):
    """
    Профиль Telegram пользователя, связанный с стандартной моделью User
    """
    
    # Связь с стандартной моделью User
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='telegram_profile',
        verbose_name="Django User"
    )
    
    # Telegram поля
    telegram_id = models.BigIntegerField(
        unique=True,
        verbose_name="Telegram ID",
        help_text="Уникальный идентификатор пользователя в Telegram"
    )
    
    telegram_username = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        verbose_name="Telegram Username"
    )
    
    telegram_first_name = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        verbose_name="Telegram First Name"
    )
    
    telegram_last_name = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        verbose_name="Telegram Last Name"
    )
    
    telegram_photo_url = models.URLField(
        max_length=500,
        null=True,
        blank=True,
        verbose_name="Telegram Photo URL"
    )
    
    telegram_auth_date = models.DateTimeField(
        default=timezone.now,
        verbose_name="Last Telegram Auth Date"
    )
    
    telegram_data = models.JSONField(
        default=dict,
        blank=True,
        verbose_name="Telegram Raw Data"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "Telegram User Profile"
        verbose_name_plural = "Telegram User Profiles"
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Telegram: {self.telegram_username or f'ID {self.telegram_id}'}"