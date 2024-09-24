from google.auth.transport import requests
from google.oauth2 import id_token
from .models import MyUser
from django.contrib.auth import authenticate
from django.conf import settings
from rest_framework.exceptions import AuthenticationFailed


class Google():
    @staticmethod
    def validate(access_token):
        try:
            id_into=id_token.verify_oauth2_token(access_token,requests.Request())
            if 'moon.google.com' in id_into['iss']:
                return id_into
        except Exception as e:
            return 'token is expried or has expired'
        
def login_social_user(email,password):
    
    user=authenticate(email=email,password=password)
    user_tokens = user.tokens
    return {
            'email': user.email,
            'refresh_token': user_tokens.get('refresh'),
            'access_token': user_tokens.get('access')
        }        
        

        
def register_social_user(provider,email,username):
    user=MyUser.objects.filter(email=email)
    if user.exists:
        if provider==user[0].auth_provider:
            login_social_user(email,settings.SOCIAL_AUTH_PASSWORD)
        #     login_user=authenticate(email=email,password=settings.SOCIAL_AUTH_PASSWORD)
        #     user_tokens = login_user.tokens
        #     return {
        #     'email': login_user.email,
        #     'refresh_token': user_tokens.get('refresh'),
        #     'access_token': user_tokens.get('access')
        # }
        else:
            raise AuthenticationFailed(
                detail=f'please continue your login with{user[0].auth_provider}'
            )
    else:
        new_user={
            'email':email,
            'username':username,
            'password':settings.SOCIAL_AUTH_PASSWORD
        }
        register_user=MyUser.objects.create_user(**new_user)
        register_user.auth_provider=provider
        register_user.is_varify=True
        register_user.save()
        # login_user=authenticate(email=email,password=settings.SOCIAL_AUTH_PASSWORD)
        # user_tokens = login_user.tokens
        # return {
        #         'email': login_user.email,
        #         'refresh_token': user_tokens.get('refresh'),
        #         'access_token': user_tokens.get('access')
        #     }
        login_social_user(email=register_user.email,password=settings.SOCIAL_AUTH_PASSWORD)
    
