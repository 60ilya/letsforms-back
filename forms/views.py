from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from django.utils import timezone
from django.db.models import Count
from django.shortcuts import get_object_or_404
from django.db import transaction
from django.db import models
from django.contrib.auth.models import User
from .models import UserProfile, Form, Question, Response as FormResponse, FormVisit
from .serializers import *

class UserProfileViewSet(viewsets.ModelViewSet):
    queryset = UserProfile.objects.all()
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False):
            return UserProfile.objects.none()
        return UserProfile.objects.filter(deleted_at__isnull=True)

    def perform_destroy(self, instance):
        instance.deleted_at = timezone.now()
        instance.save()

class FormViewSet(viewsets.ModelViewSet):
    serializer_class = FormSerializer
    permission_classes = [AllowAny]
    lookup_field = 'hash'  # Используем hash вместо id
    lookup_url_kwarg = 'hash'  # В URL будет hash вместо pk

    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False):
            return Form.objects.none()
        
        # Для аутентифицированных пользователей - их формы
        if self.request.user.is_authenticated:
            return Form.objects.filter(deleted_at__isnull=True, user=self.request.user)
        
        # Для неаутентифицированных - пустой queryset
        return Form.objects.none()

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return FormDetailSerializer
        return FormSerializer

    def get_permissions(self):
        """Разные права для разных действий"""
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            # Для создания/обновления/удаления - только по tg_id
            return [AllowAny()]
        elif self.action in ['list', 'retrieve']:
            # Для просмотра списка и деталей - аутентификация
            return [IsAuthenticated()]
        elif self.action in ['public', 'submit', 'submit_by_hash']:
            # Для публичного доступа и отправки ответов - без аутентификации
            return [AllowAny()]
        return super().get_permissions()

    def get_serializer_context(self):
        """Передаем tg_id из запроса в контекст сериализатора"""
        context = super().get_serializer_context()
        # Извлекаем tg_id из данных запроса
        if self.request.method in ['POST', 'PUT', 'PATCH']:
            try:
                data = self.request.data if hasattr(self.request, 'data') else {}
                context['tg_id'] = data.get('tg_id')
            except:
                pass
        return context

    def get_object(self):
        # Переопределяем для поддержки hash
        if 'hash' in self.kwargs:
            queryset = self.filter_queryset(self.get_queryset())
            obj = get_object_or_404(queryset, hash=self.kwargs['hash'])
            self.check_object_permissions(self.request, obj)
            return obj
        return super().get_object()

    def create(self, request, *args, **kwargs):
        """Создание формы по tg_id"""
        return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        """Обновление формы по hash и tg_id"""
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        """Удаление формы - только для аутентифицированных пользователей"""
        if not request.user.is_authenticated:
            return Response({
                'success': False,
                'error': 'Для удаления формы требуется аутентификация'
            }, status=status.HTTP_401_UNAUTHORIZED)
        return super().destroy(request, *args, **kwargs)

    def perform_destroy(self, instance):
        instance.deleted_at = timezone.now()
        instance.save()
        
    @action(detail=True, methods=['post'])
    def publish(self, request, hash=None):
        """
        Опубликовать форму (изменить статус на 'active')
        Доступно только владельцу формы
        """
        form = get_object_or_404(Form, hash=hash, deleted_at__isnull=True)
        
        # Проверяем права доступа
        if form.user != request.user:
            return Response({
                'success': False,
                'error': 'Вы не можете публиковать чужие формы'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Проверяем, можно ли опубликовать форму
        if form.status == 'active':
            return Response({
                'success': False,
                'error': 'Форма уже опубликована'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Проверяем, есть ли вопросы в форме
        if not form.questions.exists():
            return Response({
                'success': False,
                'error': 'Нельзя опубликовать форму без вопросов'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Проверяем, что все обязательные поля заполнены
        if not form.title:
            return Response({
                'success': False,
                'error': 'У формы должен быть заголовок'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Меняем статус на активный
        form.status = 'active'
        form.updated_at = timezone.now()
        form.save()
        
        return Response({
            'success': True,
            'message': 'Форма успешно опубликована',
            'form_hash': form.hash,
            'form_title': form.title,
            'status': form.status,
            'questions_count': form.questions.count(),
            'published_at': timezone.now().isoformat()
        })

    @action(detail=True, methods=['post'])
    def unpublish(self, request, hash=None):
        """
        Снять форму с публикации (изменить статус на 'draft' или 'paused')
        Доступно только владельцу формы
        """
        form = get_object_or_404(Form, hash=hash, deleted_at__isnull=True)
        
        # Проверяем права доступа
        if form.user != request.user:
            return Response({
                'success': False,
                'error': 'Вы не можете снимать с публикации чужие формы'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Проверяем, можно ли снять с публикации
        if form.status != 'active':
            return Response({
                'success': False,
                'error': f'Форма не опубликована (текущий статус: {form.status})'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Меняем статус на черновик или приостанавливаем
        new_status = request.data.get('status', 'draft')
        
        if new_status not in ['draft', 'paused']:
            new_status = 'draft'
        
        form.status = new_status
        form.updated_at = timezone.now()
        form.save()
        
        return Response({
            'success': True,
            'message': f'Форма снята с публикации (новый статус: {new_status})',
            'form_hash': form.hash,
            'form_title': form.title,
            'status': form.status,
            'unpublished_at': timezone.now().isoformat()
        })

    @action(detail=True, methods=['post'])
    def archive(self, request, hash=None):
        """
        Архивировать форму
        Доступно только владельцу формы
        """
        form = get_object_or_404(Form, hash=hash, deleted_at__isnull=True)
        
        # Проверяем права доступа
        if form.user != request.user:
            return Response({
                'success': False,
                'error': 'Вы не можете архивировать чужие формы'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Меняем статус на архивный
        form.status = 'archived'
        form.updated_at = timezone.now()
        form.save()
        
        return Response({
            'success': True,
            'message': 'Форма успешно архивирована',
            'form_hash': form.hash,
            'form_title': form.title,
            'status': form.status,
            'archived_at': timezone.now().isoformat()
        })
        
    @action(detail=True, methods=['get'])
    def publish_check(self, request, hash=None):
        """
        Проверить, готова ли форма к публикации
        Возвращает список требований и их статус
        """
        form = get_object_or_404(Form, hash=hash, deleted_at__isnull=True)
        
        # Проверяем права доступа
        if form.user != request.user:
            return Response({
                'success': False,
                'error': 'Вы не можете проверять чужие формы'
            }, status=status.HTTP_403_FORBIDDEN)
        
        requirements = []
        
        # 1. Проверка заголовка
        requirements.append({
            'requirement': 'Заголовок формы',
            'status': 'success' if form.title else 'error',
            'message': 'Заголовок установлен' if form.title else 'Требуется заголовок'
        })
        
        # 2. Проверка наличия вопросов
        questions_count = form.questions.count()
        requirements.append({
            'requirement': 'Вопросы в форме',
            'status': 'success' if questions_count > 0 else 'error',
            'message': f'Найдено {questions_count} вопросов' if questions_count > 0 else 'Требуется хотя бы один вопрос'
        })
        
        # 3. Проверка обязательных вопросов (если есть)
        required_questions = form.questions.filter(is_required=True)
        requirements.append({
            'requirement': 'Обязательные вопросы',
            'status': 'success' if required_questions.exists() else 'warning',
            'message': f'Найдено {required_questions.count()} обязательных вопросов' if required_questions.exists() else 'Рекомендуется добавить обязательные вопросы'
        })
        
        # 4. Проверка различных типов вопросов
        question_types = form.questions.values_list('type', flat=True).distinct()
        question_types_count = len(question_types)
        requirements.append({
            'requirement': 'Разнообразие типов вопросов',
            'status': 'success' if question_types_count > 1 else 'warning',
            'message': f'Найдено {question_types_count} различных типов вопросов' if question_types_count > 1 else 'Рекомендуется добавить вопросы разных типов'
        })
        
        # 5. Проверка описания (опционально)
        requirements.append({
            'requirement': 'Описание формы',
            'status': 'success' if form.description else 'warning',
            'message': 'Описание установлено' if form.description else 'Рекомендуется добавить описание'
        })
        
        # 6. Проверка текущего статуса
        requirements.append({
            'requirement': 'Текущий статус',
            'status': 'info',
            'message': f'Текущий статус: {form.get_status_display()}'
        })
        
        # Определяем общий статус
        has_errors = any(r['status'] == 'error' for r in requirements)
        has_warnings = any(r['status'] == 'warning' for r in requirements)
        
        overall_status = 'ready'
        if has_errors:
            overall_status = 'not_ready'
        elif has_warnings:
            overall_status = 'ready_with_warnings'
        
        return Response({
            'success': True,
            'form_hash': form.hash,
            'form_title': form.title,
            'overall_status': overall_status,
            'can_publish': not has_errors,
            'requirements': requirements,
            'statistics': {
                'questions_count': questions_count,
                'required_questions_count': required_questions.count(),
                'question_types_count': question_types_count,
                'question_types': list(question_types)
            }
        })
        
    def _track_visit(self, form, request, user_profile=None):
        """Отслеживание посещения формы"""
        try:
            ip_address = request.META.get('REMOTE_ADDR')
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            referrer = request.META.get('HTTP_REFERER', '')
            
            FormVisit.objects.create(
                form=form,
                user_profile=user_profile,
                ip_address=ip_address,
                user_agent=user_agent[:500],  # Ограничиваем длину
                referrer=referrer[:500] if referrer else None
            )
        except Exception as e:
            # Логируем ошибку, но не прерываем выполнение
            print(f"Ошибка при отслеживании посещения: {e}")

    @action(detail=True, methods=['get'], permission_classes=[AllowAny])
    def public(self, request, hash=None):
        """Публичный доступ к активной форме со статистикой"""
        form = get_object_or_404(Form, hash=hash, status='active', deleted_at__isnull=True)
        
        # Трекаем посещение (без user_profile для анонимных пользователей)
        self._track_visit(form, request)
        
        serializer = FormDetailSerializer(form, context={'request': request})
        response_data = serializer.data
        
        # Добавляем статистику
        response_data['statistics'] = {
            'visit_count': form.visit_count,
            'response_count': form.response_count,
            'conversion_rate': form.conversion_rate,
            'bounce_rate': form.bounce_rate
        }
        
        return Response(response_data)

    @action(detail=True, methods=['post'], permission_classes=[AllowAny])
    def submit(self, request, hash=None):
        """Отправка ответов на форму по hash"""
        form = get_object_or_404(Form, hash=hash, status='active', deleted_at__isnull=True)
        serializer = SubmitFormSerializer(data=request.data)
        
        if serializer.is_valid():
            try:
                with transaction.atomic():
                    tg_id = serializer.validated_data['tg_id']
                    
                    try:
                        user_profile = UserProfile.objects.get(
                            telegram_id=tg_id, 
                            deleted_at__isnull=True
                        )
                    except UserProfile.DoesNotExist:
                        return Response({
                            'success': False,
                            'error': f'Пользователь с Telegram ID {tg_id} не найден'
                        }, status=status.HTTP_400_BAD_REQUEST)
                    
                    responses_created = 0
                    responses_updated = 0
                    
                    for response_data in serializer.validated_data['responses']:
                        existing_response = FormResponse.objects.filter(
                            form=form,
                            user_profile=user_profile,
                            question=response_data['question']
                        ).first()
                        
                        if existing_response:
                            existing_response.answer = response_data['answer']
                            existing_response.save()
                            responses_updated += 1
                        else:
                            FormResponse.objects.create(
                                form=form,
                                user_profile=user_profile,
                                question=response_data['question'],
                                answer=response_data['answer']
                            )
                            responses_created += 1
                    
                    return Response({
                        'success': True,
                        'tg_id': tg_id,
                        'user_id': user_profile.user.id,
                        'username': user_profile.user.username,
                        'form_hash': form.hash,
                        'responses_created': responses_created,
                        'responses_updated': responses_updated,
                        'total': responses_created + responses_updated,
                        'message': 'Ответы успешно сохранены'
                    }, status=status.HTTP_201_CREATED)
                    
            except Exception as e:
                return Response({
                    'success': False,
                    'error': str(e)
                }, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['get'])
    def responses(self, request, hash=None):
        """Получение всех ответов на форму (только для владельца)"""
        form = get_object_or_404(Form, hash=hash, deleted_at__isnull=True)
        
        # Если пользователь аутентифицирован и это его форма
        if request.user.is_authenticated and form.user == request.user:
            responses = form.responses.all()
            serializer = ResponseSerializer(responses, many=True)
            return Response({
                'success': True,
                'form_hash': form.hash,
                'form_title': form.title,
                'count': responses.count(),
                'responses': serializer.data
            })
        
        # Если неаутентифицирован, проверяем по tg_id
        tg_id = request.query_params.get('tg_id')
        if not tg_id:
            return Response({
                'success': False,
                'error': 'Требуется аутентификация или tg_id'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        try:
            user_profile = UserProfile.objects.get(
                telegram_id=tg_id, 
                deleted_at__isnull=True
            )
            
            # Проверяем, что форма принадлежит этому пользователю
            if form.user != user_profile.user:
                return Response({
                    'success': False,
                    'error': 'Вы не можете просматривать ответы на чужие формы'
                }, status=status.HTTP_403_FORBIDDEN)
            
            responses = form.responses.filter(user_profile=user_profile)
            serializer = ResponseSerializer(responses, many=True)
            
            return Response({
                'success': True,
                'tg_id': tg_id,
                'user_id': user_profile.user.id,
                'username': user_profile.user.username,
                'form_hash': form.hash,
                'count': responses.count(),
                'responses': serializer.data
            })
            
        except UserProfile.DoesNotExist:
            return Response({
                'success': False,
                'error': f'Пользователь с Telegram ID {tg_id} не найден'
            }, status=status.HTTP_404_NOT_FOUND)
    
    @action(detail=False, methods=['get'], permission_classes=[AllowAny])
    def by_tg_id(self, request):
        """Получить формы пользователя по Telegram ID со статистикой"""
        tg_id = request.query_params.get('tg_id')
        
        if not tg_id:
            return Response({
                'success': False,
                'error': 'tg_id обязателен'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            profile = UserProfile.objects.get(telegram_id=tg_id, deleted_at__isnull=True)
            user = profile.user
            forms = Form.objects.filter(user=user, deleted_at__isnull=True)
            
            # Трекаем посещения для всех форм пользователя
            for form in forms:
                self._track_visit(form, request, profile)
            
            # Получаем общую статистику по всем формам пользователя
            total_forms = forms.count()
            total_visits = FormVisit.objects.filter(form__in=forms).count()
            total_responses = FormResponse.objects.filter(form__in=forms).count()
            
            # Расчет общей конверсии и отказов
            overall_conversion_rate = 0
            if total_visits > 0:
                overall_conversion_rate = round((total_responses / total_visits) * 100, 2)
            
            # Подсчет уникальных респондентов
            unique_respondents = FormResponse.objects.filter(
                form__in=forms
            ).values('user_profile').distinct().count()
            
            overall_bounce_rate = 0
            if total_visits > 0:
                overall_bounce_rate = round(((total_visits - unique_respondents) / total_visits) * 100, 2)
            
            # Статистика по статусам форм
            active_forms_count = forms.filter(status='active').count()
            draft_forms_count = forms.filter(status='draft').count()
            
            # Используем пагинацию для форм
            page = self.paginate_queryset(forms)
            if page is not None:
                serializer = FormSerializer(page, many=True, context={'request': request})
                response_data = self.get_paginated_response(serializer.data)
                # Добавляем общую статистику в ответ
                response_data.data['user_statistics'] = {
                    'total_forms': total_forms,
                    'total_visits': total_visits,
                    'total_responses': total_responses,
                    'overall_conversion_rate': overall_conversion_rate,
                    'overall_bounce_rate': overall_bounce_rate,
                    'active_forms_count': active_forms_count,
                    'draft_forms_count': draft_forms_count,
                    'user_id': user.id,
                    'username': user.username,
                    'telegram_id': tg_id
                }
                return response_data
            
            serializer = FormSerializer(forms, many=True, context={'request': request})
            
            return Response({
                'success': True,
                'user_statistics': {
                    'total_forms': total_forms,
                    'total_visits': total_visits,
                    'total_responses': total_responses,
                    'overall_conversion_rate': overall_conversion_rate,
                    'overall_bounce_rate': overall_bounce_rate,
                    'active_forms_count': active_forms_count,
                    'draft_forms_count': draft_forms_count,
                    'user_id': user.id,
                    'username': user.username,
                    'telegram_id': tg_id
                },
                'forms': serializer.data,
                'count': forms.count()
            })
            
        except UserProfile.DoesNotExist:
            return Response({
                'success': False,
                'error': f'Пользователь с Telegram ID {tg_id} не найден'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['get'], permission_classes=[AllowAny], url_path='hash/(?P<hash>[^/.]+)')
    def by_hash(self, request, hash=None):
        """Получение формы по hash (публичный доступ) со статистикой"""
        try:
            form = Form.objects.get(hash=hash, deleted_at__isnull=True)
            
            # Трекаем посещение
            self._track_visit(form, request)
            
            serializer = FormDetailSerializer(form, context={'request': request})
            response_data = serializer.data
            
            # Добавляем статистику
            response_data['statistics'] = {
                'visit_count': form.visit_count,
                'response_count': form.response_count,
                'conversion_rate': form.conversion_rate,
                'bounce_rate': form.bounce_rate
            }
            
            return Response({
                'success': True,
                'form': response_data,
                'public_url': request.build_absolute_uri(f'/forms/{hash}/')
            })
            
        except Form.DoesNotExist:
            return Response({
                'success': False,
                'error': f'Форма с хешем {hash} не найдена'
            }, status=status.HTTP_404_NOT_FOUND)

    @action(detail=True, methods=['get'])
    def detailed_statistics(self, request, hash=None):
        """Детальная статистика по форме"""
        form = get_object_or_404(Form, hash=hash, user=request.user, deleted_at__isnull=True)
        
        # Детальная статистика
        visits_by_day = FormVisit.objects.filter(
            form=form, 
            created_at__date__gte=timezone.now().date() - timezone.timedelta(days=30)
        ).extra({'day': "date(created_at)"}).values('day').annotate(count=Count('id'))
        
        responses_by_day = FormResponse.objects.filter(
            form=form,
            created_at__date__gte=timezone.now().date() - timezone.timedelta(days=30)
        ).extra({'day': "date(created_at)"}).values('day').annotate(count=Count('id'))
        
        # Топ вопросов по ответам
        question_stats = Question.objects.filter(form=form).annotate(
            answer_count=Count('responses')
        ).order_by('-answer_count')[:10]
        
        return Response({
            'success': True,
            'form_hash': form.hash,
            'form_title': form.title,
            'basic_stats': {
                'visit_count': form.visit_count,
                'response_count': form.response_count,
                'conversion_rate': form.conversion_rate,
                'bounce_rate': form.bounce_rate,
                'unique_visitors': form.visits.values('user_profile').distinct().count(),
                'unique_respondents': form.responses.values('user_profile').distinct().count()
            },
            'visits_by_day': list(visits_by_day),
            'responses_by_day': list(responses_by_day),
            'question_stats': [
                {
                    'question_id': q.id,
                    'question_text': q.text[:100],
                    'answer_count': q.answer_count
                }
                for q in question_stats
            ]
        })

    @action(detail=False, methods=['get'], permission_classes=[AllowAny])
    def search(self, request):
        """Поиск форм по хешу или названию"""
        query = request.query_params.get('q', '')
        tg_id = request.query_params.get('tg_id')
        
        forms = Form.objects.filter(deleted_at__isnull=True)
        
        if query:
            forms = forms.filter(
                models.Q(hash__icontains=query) |
                models.Q(title__icontains=query) |
                models.Q(description__icontains=query)
            )
        
        if tg_id:
            try:
                user_profile = UserProfile.objects.get(
                    telegram_id=tg_id, 
                    deleted_at__isnull=True
                )
                forms = forms.filter(user=user_profile.user)
            except UserProfile.DoesNotExist:
                return Response({
                    'success': False,
                    'error': f'Пользователь с Telegram ID {tg_id} не найден'
                }, status=status.HTTP_404_NOT_FOUND)
        
        serializer = FormSerializer(forms, many=True, context={'request': request})
        
        return Response({
            'success': True,
            'count': forms.count(),
            'query': query,
            'forms': serializer.data
        })
            
    @action(detail=True, methods=['post'], permission_classes=[AllowAny])
    def add_questions(self, request, hash=None):
        """
        Массовое добавление вопросов в форму по hash
        """
        form = get_object_or_404(Form, hash=hash, deleted_at__isnull=True)
        
        # Проверяем, что форма принадлежит пользователю (по tg_id или auth)
        tg_id = request.data.get('tg_id')
        
        if tg_id:
            # Проверка по Telegram ID
            try:
                user_profile = UserProfile.objects.get(
                    telegram_id=tg_id, 
                    deleted_at__isnull=True
                )
                if form.user != user_profile.user:
                    return Response({
                        'success': False,
                        'error': 'Вы не можете добавлять вопросы в чужую форму'
                    }, status=status.HTTP_403_FORBIDDEN)
            except UserProfile.DoesNotExist:
                return Response({
                    'success': False,
                    'error': f'Пользователь с Telegram ID {tg_id} не найден'
                }, status=status.HTTP_400_BAD_REQUEST)
        elif request.user.is_authenticated:
            # Проверка по аутентификации
            if form.user != request.user:
                return Response({
                    'success': False,
                    'error': 'Вы не можете добавлять вопросы в чужую форму'
                }, status=status.HTTP_403_FORBIDDEN)
        else:
            return Response({
                'success': False,
                'error': 'Требуется аутентификация или указание tg_id'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        serializer = BulkQuestionSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response({
                'success': False,
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            with transaction.atomic():
                created_questions = []
                for question_data in serializer.validated_data['questions']:
                    # Устанавливаем форму для вопроса (важный момент!)
                    question_data['form'] = form
                    question = Question.objects.create(**question_data)
                    created_questions.append(question)
                
                # Сериализуем созданные вопросы для ответа
                question_serializer = QuestionSerializer(created_questions, many=True)
                
                return Response({
                    'success': True,
                    'message': f'Успешно добавлено {len(created_questions)} вопросов',
                    'form_hash': form.hash,
                    'form_title': form.title,
                    'questions_added': len(created_questions),
                    'questions': question_serializer.data
                }, status=status.HTTP_201_CREATED)
                
        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=True, methods=['post'])
    def add_questions_batch(self, request, hash=None):
        """
        Альтернативный метод: добавление вопросов с валидацией по сериализатору
        """
        form = get_object_or_404(Form, hash=hash, deleted_at__isnull=True)
        
        # Проверяем права доступа
        if form.user != request.user:
            return Response({
                'success': False,
                'error': 'Вы не можете добавлять вопросы в чужую форму'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Ожидаем массив вопросов напрямую
        questions_data = request.data if isinstance(request.data, list) else request.data.get('questions', [])
        
        if not questions_data:
            return Response({
                'success': False,
                'error': 'Необходим массив вопросов'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            with transaction.atomic():
                created_questions = []
                errors = []
                
                for i, question_data in enumerate(questions_data):
                    # Добавляем форму к данным вопроса
                    question_data['form'] = form.id
                    
                    serializer = QuestionSerializer(data=question_data)
                    if serializer.is_valid():
                        question = serializer.save(form=form)
                        created_questions.append(question)
                    else:
                        errors.append({
                            'question_number': i + 1,
                            'data': question_data,
                            'errors': serializer.errors
                        })
                
                if errors and not created_questions:
                    # Если все вопросы с ошибками
                    return Response({
                        'success': False,
                        'message': 'Все вопросы содержат ошибки',
                        'errors': errors
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                question_serializer = QuestionSerializer(created_questions, many=True)
                
                response_data = {
                    'success': True,
                    'message': f'Успешно добавлено {len(created_questions)} вопросов',
                    'form_hash': form.hash,
                    'questions_added': len(created_questions),
                    'questions': question_serializer.data
                }
                
                if errors:
                    response_data['partial_success'] = True
                    response_data['failed_count'] = len(errors)
                    response_data['errors'] = errors
                
                return Response(response_data, status=status.HTTP_201_CREATED)
                
        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
            
    @action(detail=True, methods=['put'])
    def replace_questions(self, request, hash=None):
        """
        Полная замена всех вопросов в форме
        (удаляет старые и добавляет новые)
        """
        form = get_object_or_404(Form, hash=hash, deleted_at__isnull=True)
        
        # Проверяем права доступа
        if form.user != request.user:
            return Response({
                'success': False,
                'error': 'Вы не можете изменять вопросы в чужой форме'
            }, status=status.HTTP_403_FORBIDDEN)
        
        questions_data = request.data if isinstance(request.data, list) else request.data.get('questions', [])
        
        if not questions_data:
            return Response({
                'success': False,
                'error': 'Необходим массив вопросов'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            with transaction.atomic():
                # Удаляем все существующие вопросы
                deleted_count, _ = form.questions.all().delete()
                
                # Создаем новые вопросы
                created_questions = []
                for question_data in questions_data:
                    question_data['form'] = form.id
                    serializer = QuestionSerializer(data=question_data)
                    
                    if serializer.is_valid():
                        question = serializer.save(form=form)
                        created_questions.append(question)
                    else:
                        # Если есть ошибка - откатываем транзакцию
                        raise serializers.ValidationError(serializer.errors)
                
                question_serializer = QuestionSerializer(created_questions, many=True)
                
                return Response({
                    'success': True,
                    'message': f'Заменено {deleted_count} вопросов на {len(created_questions)} новых',
                    'form_hash': form.hash,
                    'questions_deleted': deleted_count,
                    'questions_added': len(created_questions),
                    'questions': question_serializer.data
                }, status=status.HTTP_200_CREATED)
                
        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=True, methods=['delete'])
    def clear_questions(self, request, hash=None):
        """
        Удаление всех вопросов из формы
        """
        form = get_object_or_404(Form, hash=hash, deleted_at__isnull=True)
        
        # Проверяем права доступа
        if form.user != request.user:
            return Response({
                'success': False,
                'error': 'Вы не можете удалять вопросы из чужой формы'
            }, status=status.HTTP_403_FORBIDDEN)
        
        try:
            count, _ = form.questions.all().delete()
            
            return Response({
                'success': True,
                'message': f'Удалено {count} вопросов',
                'form_hash': form.hash,
                'questions_deleted': count
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

class QuestionViewSet(viewsets.ModelViewSet):
    serializer_class = QuestionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False):
            return Question.objects.none()
        
        # Фильтруем вопросы только для форм текущего пользователя
        if self.request.user.is_authenticated:
            return Question.objects.filter(form__user=self.request.user)
        return Question.objects.none()

    def perform_create(self, serializer):
        form = serializer.validated_data['form']
        if form.user != self.request.user:
            raise PermissionDenied("Вы не можете добавлять вопросы в чужие формы")
        serializer.save()

class ResponseViewSet(viewsets.ModelViewSet):
    serializer_class = ResponseSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False):
            return FormResponse.objects.none()
        return FormResponse.objects.filter(form__user=self.request.user)

    @action(detail=False, methods=['get'])
    def by_tg_id(self, request):
        """Получение ответов по Telegram ID"""
        tg_id = request.query_params.get('tg_id')
        form_hash = request.query_params.get('form_hash')  # Теперь используем form_hash вместо form_id
        
        if not tg_id:
            return Response({'error': 'tg_id обязателен'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user_profile = UserProfile.objects.get(
                telegram_id=tg_id, 
                deleted_at__isnull=True
            )
        except UserProfile.DoesNotExist:
            return Response({
                'success': False,
                'error': f'Пользователь с Telegram ID {tg_id} не найден'
            }, status=status.HTTP_404_NOT_FOUND)
        
        responses = FormResponse.objects.filter(
            user_profile=user_profile,
            form__user=request.user
        )
        
        if form_hash:
            responses = responses.filter(form__hash=form_hash)
        
        serializer = self.get_serializer(responses, many=True)
        
        return Response({
            'success': True,
            'tg_id': tg_id,
            'user_id': user_profile.user.id,
            'username': user_profile.user.username,
            'count': responses.count(),
            'responses': serializer.data
        })
    
    @action(detail=False, methods=['get'])
    def by_form_hash(self, request):
        """Получение всех ответов на форму по hash"""
        form_hash = request.query_params.get('form_hash')
        
        if not form_hash:
            return Response({'error': 'form_hash обязателен'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            form = Form.objects.get(hash=form_hash, user=request.user)
        except Form.DoesNotExist:
            return Response({
                'success': False,
                'error': f'Форма с хешем {form_hash} не найдена или у вас нет к ней доступа'
            }, status=status.HTTP_404_NOT_FOUND)
        
        responses = form.responses.all()
        serializer = self.get_serializer(responses, many=True)
        
        return Response({
            'success': True,
            'form_hash': form.hash,
            'form_title': form.title,
            'count': responses.count(),
            'responses': serializer.data
        })