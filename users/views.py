from .serializers import RegisterSerializer
from .serializers import LoginSerializer
from django.http import JsonResponse
from .models import User
from rest_framework import generics
from . import serializers
from rest_framework.response import Response
from rest_framework import status
from rest_framework import views
from rest_framework import permissions
from django.contrib.auth import login

class SignUpView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    

class LoginView(views.APIView):
    # This view should be accessible also for unauthenticated users.
    permission_classes = (permissions.AllowAny,)

    def post(self, request, format=None):
        serializer = serializers.LoginSerializer(data=self.request.data,
            context={ 'request': self.request })
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        login(request, user)
        #Check login is successful or not
        return Response(None, status=status.HTTP_200_OK) 
