from rest_framework import serializers
from .models import MyUser
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import smart_str,smart_bytes
from .utils import send_normal_email
from django.urls import reverse
from .social import Google,register_social_user
from.microsoft import GoogleAuth,MicrosoftAuth
from django.conf import settings




class UserregisterSerializer(serializers.ModelSerializer):
    password2=serializers.CharField(max_length=250,write_only=True)
    class Meta:
        model=MyUser
        fields = ['email', 'username', 'password', 'password2']
        extra_kwargs = {
            'password': {'write_only': True}
        }
        
    def validate(self,atts):
        password=atts.get('password', '')
        password2=atts.get('password2','')
        if password!=password2:
            raise serializers.ValidationError('password do not match')
        return atts
    
    
    def create(self,validated_data):
        # user=MyUser.objects.create_user(**validated_data)
        validated_data.pop('password2')
        user=MyUser.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            username=validated_data['username']
        )
        return user
    
class Loginseriazer(serializers.ModelSerializer):
    email=serializers.EmailField(max_length=50,min_length=6)
    password=serializers.CharField(max_length=250,write_only=True)
    access_token=serializers.CharField(max_length=250,read_only=True)
    refresh_token=serializers.CharField(max_length=250,read_only=True)
    
    class Meta:
        model= MyUser
        fields=['email','password','refresh_token','access_token']
        
    def validate(self,attrs):
        email=attrs.get('email')
        password=attrs.get('password')
        request=self.context.get('request')
        user = authenticate(request,email=email,password=password)
        if not user:
            raise AuthenticationFailed({'msg':'invalid authenticate'})
        user_tokens = user.tokens
        
        return {
        'email': user.email,
        'refresh_token': user_tokens.get('refresh'),
        'access_token': user_tokens.get('access')
    }
                
class ResetPasswordSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=50, min_length=6)

    class Meta:
        model = MyUser
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        if MyUser.objects.filter(email=email).exists():
            user = MyUser.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            request = self.context.get('request')
            site_domain = get_current_site(request).domain
            relative_link = reverse("password-reset-confirm", kwargs={'uidb64': uidb64, 'token': token})
            abslink = f"http://{site_domain}{relative_link}"
            email_body = f'Hi, reset your password by clicking the link below:\n{abslink}'
            data = {
                'email_body': email_body,
                'email_subject': 'Reset your password',
                'to_email': user.email
            }
            # Assuming send_normal_email is defined elsewhere
            send_normal_email(data)
        
        return attrs
    
    
class GooglesigninSerializer(serializers.ModelSerializer):
    access_token=serializers.CharField(min_length=6)
    
    # class Meta:
    #     model = MyUser  # Replace MyUser with your actual User model
    #     fields = ['email','access_token'] 
    
    def validate_access_token(self, access_token):
        google_user_data=Google.validate(access_token)
        
        try:
            google_user_data['sub']
            
        
        except:
            raise serializers.ValidationError('this token is invalid or exride ')
        if google_user_data['aud']!=settings.GOOGLE_CLINT_ID:
            raise AuthenticationFailed(detail='coulld not varify user')
        email=google_user_data['email']
        username=google_user_data['fullname']
        provider='google'
        return register_social_user(provider,email,username)
    
    
class SocialSignInSerializer(serializers.ModelSerializer):
    access_token = serializers.CharField(min_length=6)
    provider = serializers.ChoiceField(choices=['google', 'microsoft'])

    def validate(self, data):
        access_token = data.get('access_token')
        provider = data.get('provider')

        # Validate based on the provider
        if provider == 'google':
            user_data = GoogleAuth.validate(access_token)
            if not user_data.get('sub'):
                raise serializers.ValidationError('This Google token is invalid or expired.')
            if user_data.get('aud') != settings.GOOGLE_CLIENT_ID:
                raise AuthenticationFailed(detail='Google token verification failed.')
            email = user_data.get('email')
            username = user_data.get('name')  # Assuming 'name' is the full name
        elif provider == 'microsoft':
            user_data = MicrosoftAuth.validate(access_token)
            if not user_data.get('id'):
                raise serializers.ValidationError('This Microsoft token is invalid or expired.')
            email = user_data.get('mail', user_data.get('userPrincipalName'))
            username = user_data.get('displayName')
        else:
            raise serializers.ValidationError('Unsupported provider.')

        # Register or login the user
        return register_social_user(provider, email, username)