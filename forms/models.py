from django.db import models
from django.contrib.auth.models import User
import secrets
import string
from django.utils.crypto import get_random_string

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    telegram_id = models.BigIntegerField(unique=True, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.user.username} (TG: {self.telegram_id})"

class Form(models.Model):
    FORM_TYPES = [
        ('survey', 'Опрос'),
        ('quiz', 'Тест'),
        ('feedback', 'Обратная связь'),
        ('registration', 'Регистрация'),
    ]
    
    STATUS_CHOICES = [
        ('draft', 'Черновик'),
        ('active', 'Активна'),
        ('paused', 'Приостановлена'),
        ('archived', 'В архиве'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='forms')
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    type = models.CharField(max_length=20, choices=FORM_TYPES, default='survey')
    hash = models.CharField(max_length=8, unique=True, editable=False, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.title} ({self.hash})"

    def clean(self):
        """Валидация перед сохранением"""
        if not self.hash:
            self.hash = self.generate_unique_hash()
    
    def save(self, *args, **kwargs):
        """Генерируем уникальный хеш при создании формы"""
        if not self.hash or self.hash == '':
            self.hash = self.generate_unique_hash()
        super().save(*args, **kwargs)
        
    def generate_unique_hash(self):
        """Генерирует уникальный 8-значный хеш"""

        return get_random_string(8, allowed_chars='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
    
    @property
    def visit_count(self):
        """Количество посещений формы"""
        return FormVisit.objects.filter(form=self).count()

    @property
    def response_count(self):
        """Количество ответов на форму"""
        return self.responses.count()

    @property
    def conversion_rate(self):
        """Конверсия (ответы / посещения * 100%)"""
        visits = self.visit_count
        if visits == 0:
            return 0
        return round((self.response_count / visits) * 100, 2)

    @property
    def bounce_rate(self):
        """Процент отказов (посетители, которые не ответили)"""
        visits = self.visit_count
        if visits == 0:
            return 0
        respondents = self.responses.values('user_profile').distinct().count()
        return round(((visits - respondents) / visits) * 100, 2)
    
    @property
    def public_url(self):
        """Возвращает публичную URL форму"""
        from django.urls import reverse
        # Или ваш домен
        return f"/forms/{self.hash}/"
    
class FormVisit(models.Model):
    """Модель для отслеживания посещений форм"""
    form = models.ForeignKey(Form, on_delete=models.CASCADE, related_name='visits')
    user_profile = models.ForeignKey(UserProfile, on_delete=models.CASCADE, 
                                     related_name='form_visits', null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, null=True)
    referrer = models.URLField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['form', 'user_profile']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"Посещение формы {self.form.hash}"

class Question(models.Model):
    QUESTION_TYPES = [
        ('info', 'Информационный блок'),
        ('text', 'Текстовый ответ'),
        ('text_area', 'Текстовый ответ'),
        ('number', 'Числовой ответ'),
        ('date', 'Дата'),
        ('single_choice', 'Один вариант'),
        ('multiple_choice', 'Несколько вариантов'),

    ]

    form = models.ForeignKey(Form, on_delete=models.CASCADE, related_name='questions')
    type = models.CharField(max_length=20, choices=QUESTION_TYPES, default='text')
    text = models.TextField()
    options = models.JSONField(blank=True, null=True)
    is_required = models.BooleanField(default=True)
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['order', 'id']

    def __str__(self):
        return f"{self.text[:50]}..."

class Response(models.Model):
    form = models.ForeignKey(Form, on_delete=models.CASCADE, related_name='responses')
    user_profile = models.ForeignKey(UserProfile, on_delete=models.CASCADE, 
                                     related_name='responses', null=True, blank=True)
    question = models.ForeignKey(Question, on_delete=models.CASCADE, related_name='responses')
    answer = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        unique_together = [['user_profile', 'question']]

    def __str__(self):
        return f"Ответ на '{self.question.text}'"