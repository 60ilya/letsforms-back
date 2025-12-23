from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'users', views.UserProfileViewSet, basename='users')
router.register(r'forms', views.FormViewSet, basename='forms')
router.register(r'questions', views.QuestionViewSet, basename='questions')
router.register(r'responses', views.ResponseViewSet, basename='responses')

urlpatterns = [
    path('', include(router.urls)),
]