from google.auth.transport import requests
from google.oauth2 import id_token
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import authenticate
from .models import MyUser
from django.conf import settings

class GoogleAuth:
    @staticmethod
    def validate(access_token):
        try:
            id_info = id_token.verify_oauth2_token(access_token, requests.Request())
            if id_info['iss'] == 'https://accounts.google.com':
                return id_info
            else:
                raise AuthenticationFailed('Invalid Google token.')
        except Exception as e:
            raise AuthenticationFailed(f'Token validation failed: {str(e)}')


class MicrosoftAuth:
    @staticmethod
    def validate(access_token):
        try:
            response = requests.get(
                'https://graph.microsoft.com/v1.0/me',
                headers={'Authorization': f'Bearer {access_token}'}
            )
            if response.status_code == 200:
                return response.json()
            else:
                raise AuthenticationFailed('Invalid Microsoft token.')
        except Exception as e:
            raise AuthenticationFailed(f'Token validation failed: {str(e)}')


def login_social_user(email, password):
    user = authenticate(email=email, password=password)
    if user:
        user_tokens = user.tokens
        return {
            'email': user.email,
            'refresh_token': user_tokens.get('refresh'),
            'access_token': user_tokens.get('access')
        }
    else:
        raise AuthenticationFailed('User authentication failed.')
    
    
    
def register_social_user(provider, email, username, access_token):
    auth_classes = {
        'google': GoogleAuth,
        'microsoft': MicrosoftAuth
    }

    auth_class = auth_classes.get(provider)
    if not auth_class:
        raise AuthenticationFailed(f'Unsupported provider: {provider}')

    user_info = auth_class.validate(access_token)

    user = MyUser.objects.filter(email=email).first()
    if user:
        if provider == user.auth_provider:
            return login_social_user(email, settings.SOCIAL_AUTH_PASSWORD)
        else:
            raise AuthenticationFailed(
                detail=f'Please continue your login with {user.auth_provider}'
            )
    else:
        new_user = {
            'email': email,
            'username': username,
            'password': settings.SOCIAL_AUTH_PASSWORD
        }
        register_user = MyUser.objects.create_user(**new_user)
        register_user.auth_provider = provider
        register_user.is_varify = True
        register_user.save()

        return login_social_user(email=register_user.email, password=settings.SOCIAL_AUTH_PASSWORD)
