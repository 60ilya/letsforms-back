# telegram_auth/models.py
from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

class TelegramUserManager(models.Manager):
    """Менеджер для TelegramUser"""
    def create_user(self, telegram_id, **extra_fields):
        if not telegram_id:
            raise ValueError('Telegram ID обязателен')
        
        user = self.model(telegram_id=telegram_id, **extra_fields)
        user.set_unusable_password()  # Telegram users don't need passwords
        user.save(using=self._db)
        return user
    
    def create_superuser(self, telegram_id, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        
        return self.create_user(telegram_id, **extra_fields)


class TelegramUser(AbstractUser):
    """
    Кастомная модель пользователя для Telegram аутентификации
    с уникальными related_name для избежания конфликтов
    """
    
    # Убираем стандартные поля которые нам не нужны
    username = None
    email = models.EmailField(_("email address"), blank=True, null=True)
    
    # Telegram поля
    telegram_id = models.BigIntegerField(
        _("Telegram ID"),
        unique=True,
        db_index=True,
        help_text=_("Уникальный идентификатор пользователя в Telegram")
    )
    
    telegram_username = models.CharField(
        _("Telegram Username"),
        max_length=255,
        blank=True,
        null=True,
        help_text=_("Имя пользователя в Telegram (без @)")
    )
    
    telegram_first_name = models.CharField(
        _("Telegram First Name"),
        max_length=255,
        blank=True,
        null=True
    )
    
    telegram_last_name = models.CharField(
        _("Telegram Last Name"),
        max_length=255,
        blank=True,
        null=True
    )
    
    telegram_photo_url = models.URLField(
        _("Telegram Photo URL"),
        max_length=500,
        blank=True,
        null=True
    )
    
    telegram_auth_date = models.DateTimeField(
        _("Last Telegram Auth Date"),
        default=timezone.now
    )
    
    telegram_data = models.JSONField(
        _("Telegram Raw Data"),
        default=dict,
        blank=True,
        help_text=_("Оригинальные данные полученные от Telegram")
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
    
    objects = TelegramUserManager()
    
    # Используем telegram_id как поле для аутентификации
    USERNAME_FIELD = 'telegram_id'
    REQUIRED_FIELDS = []  # Telegram ID достаточно
    
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
            return f"Telegram User #{self.telegram_id}"
    
    def save(self, *args, **kwargs):
        # Автоматически генерируем username если нужно
        if not hasattr(self, 'username') or not self.username:
            self.username = f"tg_{self.telegram_id}"
        
        super().save(*args, **kwargs)