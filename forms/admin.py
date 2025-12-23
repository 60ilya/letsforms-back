# forms/admin.py
from django.contrib import admin
from .models import UserProfile, Form, Question, Response as FormResponse

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'telegram_id', 'created_at']

@admin.register(Form)
class FormAdmin(admin.ModelAdmin):
    list_display = ['title', 'user', 'type', 'status', 'created_at']

@admin.register(Question)
class QuestionAdmin(admin.ModelAdmin):
    list_display = ['text', 'form', 'type', 'is_required', 'order']

@admin.register(FormResponse) 
class ResponseAdmin(admin.ModelAdmin):
    list_display = ['form', 'question', 'created_at']