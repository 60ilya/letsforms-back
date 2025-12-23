# telegram_auth/models.py
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils import timezone
import json

class TelegramUserManager(BaseUserManager):
    """Кастомный менеджер для TelegramUser"""
    
    def create_user(self, telegram_id, **extra_fields):
        if not telegram_id:
            raise ValueError('Telegram ID обязателен')
        
        user = self.model(telegram_id=telegram_id, **extra_fields)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, telegram_id, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Суперюзер должен иметь is_staff=True')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Суперюзер должен иметь is_superuser=True')
        
        return self.create_user(telegram_id, **extra_fields)


# telegram_auth/models.py
from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

class TelegramUser(AbstractUser):
    """
    Кастомная модель пользователя для Telegram аутентификации
    с уникальными related_name для избежания конфликтов
    """
    
    # Telegram поля
    telegram_id = models.BigIntegerField(
        unique=True,
        null=True,
        blank=True,
        verbose_name=_("Telegram ID"),
        help_text=_("Уникальный идентификатор пользователя в Telegram")
    )
    
    telegram_username = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        verbose_name=_("Telegram Username"),
        help_text=_("Имя пользователя в Telegram (без @)")
    )
    
    telegram_first_name = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        verbose_name=_("Telegram First Name")
    )
    
    telegram_last_name = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        verbose_name=_("Telegram Last Name")
    )
    
    telegram_photo_url = models.URLField(
        max_length=500,
        null=True,
        blank=True,
        verbose_name=_("Telegram Photo URL")
    )
    
    telegram_auth_date = models.DateTimeField(
        default=timezone.now,
        verbose_name=_("Last Telegram Auth Date")
    )
    
    telegram_data = models.JSONField(
        default=dict,
        blank=True,
        verbose_name=_("Telegram Raw Data"),
        help_text=_("Оригинальные данные полученные от Telegram")
    )
    
    # Переопределяем стандартные поля
    username = models.CharField(
        _("username"),
        max_length=150,
        blank=True,
        help_text=_("Не требуется для Telegram аутентификации")
    )
    
    email = models.EmailField(
        _("email address"),
        blank=True,
        null=True
    )
    
    # Флаг для определения способа аутентификации
    is_telegram_user = models.BooleanField(
        default=True,
        verbose_name=_("Is Telegram User")
    )
    
    # ВАЖНО: Добавляем related_name для избежания конфликтов
    groups = models.ManyToManyField(
        Group,
        verbose_name=_('groups'),
        blank=True,
        help_text=_(
            'The groups this user belongs to. A user will get all permissions '
            'granted to each of their groups.'
        ),
        related_name="telegram_user_set",  # Уникальный related_name
        related_query_name="telegram_user",
    )
    
    user_permissions = models.ManyToManyField(
        Permission,
        verbose_name=_('user permissions'),
        blank=True,
        help_text=_('Specific permissions for this user.'),
        related_name="telegram_user_set",  # Уникальный related_name
        related_query_name="telegram_user",
    )
    
    class Meta:
        verbose_name = _("Telegram User")
        verbose_name_plural = _("Telegram Users")
        ordering = ['-date_joined']
        db_table = 'telegram_auth_user'  # Уникальное имя таблицы
    
    def __str__(self):
        if self.telegram_username:
            return f"@{self.telegram_username}"
        elif self.telegram_first_name:
            return f"{self.telegram_first_name} {self.telegram_last_name or ''}".strip()
        else:
            return f"Telegram User #{self.telegram_id or self.id}"
    
    def save(self, *args, **kwargs):
        # Автоматически генерируем username если не указан
        if not self.username and self.telegram_id:
            self.username = f"tg_{self.telegram_id}"
        
        # Устанавливаем is_staff = False по умолчанию для Telegram пользователей
        if not self.is_staff and not self.is_superuser:
            self.is_staff = False
        
        super().save(*args, **kwargs)
    
    @classmethod
    def create_from_telegram_data(cls, telegram_data: dict):
        """Создает пользователя из данных Telegram"""
        user_data = telegram_data
        
        telegram_id = user_data.get('id')
        if not telegram_id:
            raise ValueError("Telegram ID обязателен")
        
        # Пытаемся найти существующего пользователя
        try:
            user = cls.objects.get(telegram_id=telegram_id)
            is_new = False
            
            # Обновляем данные
            user.telegram_username = user_data.get('username', user.telegram_username)
            user.telegram_first_name = user_data.get('first_name', user.telegram_first_name)
            user.telegram_last_name = user_data.get('last_name', user.telegram_last_name)
            user.telegram_photo_url = user_data.get('photo_url', user.telegram_photo_url)
            user.telegram_data = user_data
            user.save()
            
        except cls.DoesNotExist:
            # Создаем нового пользователя
            user = cls.objects.create(
                telegram_id=telegram_id,
                telegram_username=user_data.get('username'),
                telegram_first_name=user_data.get('first_name', ''),
                telegram_last_name=user_data.get('last_name', ''),
                telegram_photo_url=user_data.get('photo_url'),
                telegram_data=user_data,
                first_name=user_data.get('first_name', ''),
                last_name=user_data.get('last_name', ''),
                is_active=True,
                is_telegram_user=True,
            )
            is_new = True
        
        return user, is_new