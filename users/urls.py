from django.urls import path
from users.views import SignUpView
from users.views import LoginView
from . import views

urlpatterns = [
    path('register/', SignUpView.as_view(), name='auth_register'),
    path('login/', LoginView.as_view(), name='login'),
]