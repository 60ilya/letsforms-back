from rest_framework import serializers
from django.contrib.auth.models import User
from .models import UserProfile, Form, Question, Response as FormResponse

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'date_joined']

class UserProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.CharField(source='user.email', read_only=True)
    
    class Meta:
        model = UserProfile
        fields = ['id', 'user', 'username', 'email', 'telegram_id', 'created_at', 'updated_at', 'deleted_at']
        read_only_fields = ['id', 'created_at', 'updated_at']

class FormSerializer(serializers.ModelSerializer):
    user_username = serializers.CharField(source='user.username', read_only=True)
    tg_id = serializers.IntegerField(write_only=True, required=True)
    hash = serializers.CharField(read_only=True)
    
    visit_count = serializers.IntegerField(read_only=True)
    response_count = serializers.IntegerField(read_only=True)
    conversion_rate = serializers.FloatField(read_only=True)
    bounce_rate = serializers.FloatField(read_only=True)
    
    class Meta:
        model = Form
        fields = [
            'hash', 'user_username', 'tg_id', 'title', 'description', 'type', 'status',
            'visit_count', 'response_count', 'conversion_rate', 'bounce_rate',
            'created_at', 'updated_at', 'deleted_at'
        ]
        read_only_fields = [
            'hash', 'user_username', 'visit_count', 'response_count', 
            'conversion_rate', 'bounce_rate', 'created_at', 'updated_at'
        ]
    
    def validate_tg_id(self, value):
        """Проверяем, существует ли пользователь с таким Telegram ID"""
        try:
            UserProfile.objects.get(telegram_id=value, deleted_at__isnull=True)
        except UserProfile.DoesNotExist:
            raise serializers.ValidationError(f"Пользователь с Telegram ID {value} не найден")
        return value
    
    def create(self, validated_data):
        """Создание формы с определением пользователя по tg_id"""
        tg_id = validated_data.pop('tg_id')
        
        try:
            user_profile = UserProfile.objects.get(telegram_id=tg_id, deleted_at__isnull=True)
            validated_data['user'] = user_profile.user
        except UserProfile.DoesNotExist:
            raise serializers.ValidationError(f"Пользователь с Telegram ID {tg_id} не найден")
        
        return super().create(validated_data)
    
    def update(self, instance, validated_data):
        """Обновление формы с проверкой прав"""
        tg_id = validated_data.pop('tg_id')
        
        try:
            user_profile = UserProfile.objects.get(telegram_id=tg_id, deleted_at__isnull=True)
        except UserProfile.DoesNotExist:
            raise serializers.ValidationError(f"Пользователь с Telegram ID {tg_id} не найден")
        
        if instance.user != user_profile.user:
            raise serializers.ValidationError("Вы не можете редактировать чужие формы")
        
        return super().update(instance, validated_data)

class QuestionSerializer(serializers.ModelSerializer):
    form_hash = serializers.CharField(source='form.hash', read_only=True)
    
    class Meta:
        model = Question
        fields = ['id', 'form', 'form_hash', 'type', 'text', 'placeholder', 'options', 'is_required', 'order']
        read_only_fields = ['id', 'form_hash']
        extra_kwargs = {
            'form': {'required': False, 'write_only': True} 
        }

class FormDetailSerializer(serializers.ModelSerializer):
    questions = QuestionSerializer(many=True, read_only=True)
    user_username = serializers.CharField(source='user.username', read_only=True)
    hash = serializers.CharField(read_only=True)  # Добавили hash
    
    # Статистика для детального просмотра
    visit_count = serializers.IntegerField(read_only=True)
    response_count = serializers.IntegerField(read_only=True)
    conversion_rate = serializers.FloatField(read_only=True)
    bounce_rate = serializers.FloatField(read_only=True)
    
    class Meta:
        model = Form
        fields = [
            'hash', 'user_username', 'title', 'description', 'type', 'status',
            'visit_count', 'response_count', 'conversion_rate', 'bounce_rate',
            'created_at', 'updated_at', 'deleted_at', 'questions'
        ]
        read_only_fields = [
            'hash', 'user_username', 'visit_count', 'response_count',
            'conversion_rate', 'bounce_rate', 'created_at', 'updated_at'
        ]
        
# Добавим новый сериализатор для статистики пользователя
class UserFormsStatisticsSerializer(serializers.Serializer):
    """Статистика по всем формам пользователя"""
    total_forms = serializers.IntegerField()
    total_visits = serializers.IntegerField()
    total_responses = serializers.IntegerField()
    overall_conversion_rate = serializers.FloatField()
    overall_bounce_rate = serializers.FloatField()
    active_forms_count = serializers.IntegerField()
    draft_forms_count = serializers.IntegerField()
    
    class Meta:
        fields = [
            'total_forms', 'total_visits', 'total_responses',
            'overall_conversion_rate', 'overall_bounce_rate',
            'active_forms_count', 'draft_forms_count'
        ]

class ResponseSerializer(serializers.ModelSerializer):
    tg_id = serializers.SerializerMethodField()
    username = serializers.SerializerMethodField()
    form_hash = serializers.CharField(source='form.hash', read_only=True)  # Используем hash вместо form_id
    
    class Meta:
        model = FormResponse
        fields = ['form_hash', 'tg_id', 'username', 'question', 'text', 'answer', 'order', 'created_at']
        read_only_fields = ['form_hash', 'created_at']
        extra_kwargs = {
            'form': {'write_only': True}  # form только для записи
        }
    
    def get_tg_id(self, obj):
        """Получаем Telegram ID из профиля пользователя"""
        if obj.user_profile and obj.user_profile.telegram_id:
            return obj.user_profile.telegram_id
        return None
    
    def get_username(self, obj):
        """Получаем username из пользователя"""
        if obj.user_profile and obj.user_profile.user:
            return obj.user_profile.user.username
        return None

class SubmitResponseSerializer(serializers.Serializer):
    question_id = serializers.IntegerField()
    answer = serializers.JSONField()

    def validate(self, data):
        question_id = data.get('question_id')
        try:
            question = Question.objects.get(id=question_id)
            data['question'] = question
        except Question.DoesNotExist:
            raise serializers.ValidationError("Вопрос не найден")
        return data

class SubmitFormSerializer(serializers.Serializer):
    tg_id = serializers.IntegerField(required=True)
    responses = SubmitResponseSerializer(many=True)
    
    def validate_tg_id(self, value):
        """Проверяем, существует ли пользователь с таким Telegram ID"""
        try:
            UserProfile.objects.get(telegram_id=value, deleted_at__isnull=True)
        except UserProfile.DoesNotExist:
            raise serializers.ValidationError(f"Пользователь с Telegram ID {value} не найден")
        return value

class BulkQuestionSerializer(serializers.Serializer):
    """Сериализатор для массового добавления вопросов"""
    tg_id = serializers.IntegerField(required=True)
    questions = serializers.ListField(
        child=serializers.DictField(),
        required=True,
        min_length=1,
        help_text="Массив вопросов"
    )
    
    def validate_questions(self, questions):
        """Валидация списка вопросов"""
        validated_questions = []
        
        for i, question_data in enumerate(questions):
            # Создаем временный сериализатор без проверки поля form
            temp_serializer = QuestionSerializer(data=question_data)
            
            # Временно убираем form из обязательных полей
            temp_serializer.fields['form'].required = False
            
            if not temp_serializer.is_valid():
                errors = temp_serializer.errors
                errors['question_number'] = i + 1
                raise serializers.ValidationError(errors)
            
            validated_questions.append(temp_serializer.validated_data)
        
        return validated_questions

# Добавим сериализатор для получения формы по hash (публичный доступ)
class PublicFormSerializer(serializers.ModelSerializer):
    questions = QuestionSerializer(many=True, read_only=True)
    hash = serializers.CharField(read_only=True)
    
    class Meta:
        model = Form
        fields = ['hash', 'title', 'description', 'type', 'questions']
        read_only_fields = ['hash', 'title', 'description', 'type']