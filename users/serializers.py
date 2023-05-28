from django.contrib.auth.models import User
from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import authenticate
from django.http import JsonResponse

from .models import Role


class RegisterSerializer(serializers.ModelSerializer):

    username = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)
    #role_name = serializers.CharField(write_only=True, required=True)


    class Meta:
        model = User
        fields = ('username', 'password', 'password2')
        

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
            

        return attrs
        
    def validate_username(self, value):
        if User.objects.filter(username__iexact=value).exists():
            raise serializers.ValidationError("A user with this username already exists.")
        return value

    def create(self, validated_data):
        

        
        user = User.objects.create(
            username=validated_data['username']
        )
        
        
        # role_name = self.context['request'].data.get('role_name')
        # role = Role.objects.create(user=user, role_name=role_name)

        # Attach the Role object to the User object
        # user.role = role
        
        
        user.set_password(validated_data['password'])
        user.save()
        
        # role = Role(user=user, role_name='role_name') 
        # role.save()

        return user
        

class RoleSerializer(serializers.ModelSerializer):
    
    role = RegisterSerializer(required=True)
    class Meta:
        model = Role
        fields = ('role_name')
        
    def create(self, validated_data):
        
        user = RegisterSerializer.create(RegisterSerializer(), validated_data)
        role, created = Role.objects.create(user=user)
        return role
    

class LoginSerializer(serializers.Serializer):
    
    username = serializers.CharField(
        label="Username",
        write_only=True
    )
    password = serializers.CharField(
        label="Password",
        write_only=True
    )

    def validate(self, attrs):
        # Take username and password from request
        username = attrs.get('username')
        password = attrs.get('password')

        if username and password:
            # Try to authenticate the user using Django auth framework.
            user = authenticate(request=self.context.get('request'),
                                username=username, password=password)
            if not user:
                # If we don't have a regular user, raise a ValidationError
                msg = 'Access denied: wrong username or password.'
                raise serializers.ValidationError(msg, code='authorization')
        else:
            msg = 'Both "username" and "password" are required.'
            raise serializers.ValidationError(msg, code='authorization')
        # We have a valid user, put it in the serializer's validated_data.
        # It will be used in the view.
        attrs['user'] = user
        
        #role = Role.objects.get(user=user)
        #data = {'username': username, 'role': role_name}
            
        #return JsonResponse(data)
        return attrs
 
