from django.shortcuts import render

from rest_framework.views import APIView
from .models import MyUser,Onetimepassword
from .serializers import UserregisterSerializer,Loginseriazer,ResetPasswordSerializer,GooglesigninSerializer
from rest_framework.response import Response
from rest_framework import status
# from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from .social import Google,register_social_user
from rest_framework.exceptions import AuthenticationFailed


# def get_tokens_for_user(user):
#   refresh = RefreshToken.for_user(user)
#   return {
#       'refresh': str(refresh),
#       'access': str(refresh.access_token),
#   }

# Create your views here.
class RegisterViews(APIView):
    serirializer_class=UserregisterSerializer
    def post(self,request):
        serializer=self.serirializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            print(serializer)
            serializer.save()
        #     user=serializer.data
        #     return Response({'msg':user},status=status.HTTP_201_CREATED)
            
        # return Response({'msg':serializer},status=status.HTTP_400_BAD_REQUEST)
            return Response({'msg': 'User registered successfully.'}, status=status.HTTP_201_CREATED)
        return Response({'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
    
class Verifyemail(APIView):
    def post(self,request):
        otecode=request.data.get('otp')
        try:
            user_object=Onetimepassword.objects.get(code=otecode)
            user=user_object.user
            if not user.is_varify:
                user.is_varify=True
                user.save()
                return Response({'msg':'email is varify sucessfully'},status=status.HTTP_200_OK)
            return Response({'msg':'already varify this email'},status=status.HTTP_204_NO_CONTENT) 
        except Onetimepassword.DoesNotExist:
            return Response({'msg':'passcode not provide'})
        
class LoginUser(APIView):
    serializer_class=Loginseriazer
    def post(self,request):
        serializer=self.serializer_class(data=request.data,context={'request':request})
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data,status=status.HTTP_200_OK)

class TestauthenicatedView(APIView):
    permission_classes=[IsAuthenticated]
    def get(self,request):
        data={
            'msg':'he is working'
        }
        return Response(data,status=status.HTTP_200_OK)
    
class Restpasswordsend(APIView):
    serializer_class=ResetPasswordSerializer
    def post(self,request):
        serializer=self.serializer_class(data=request.data,context={'request':request})
        serializer.is_valid(raise_exception=True)
        return Response({'msg':'password is changing sucessfully '})
    

    
class SocialSignInView(APIView):
    def post(self, request):
        serializer = GooglesigninSerializer(data=request.data)
        if serializer.is_valid():
            provider = serializer.validated_data['provider']
            email = serializer.validated_data['email']
            username = serializer.validated_data['username']
            access_token = serializer.validated_data['access_token']

            try:
                tokens = register_social_user(provider, email, username, access_token)
                return Response(tokens, status=status.HTTP_200_OK)
            except AuthenticationFailed as e:
                return Response({'detail': str(e)}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
class GooglesigninViews(APIView):
    serializer_class=GooglesigninSerializer
    def post(self,request):
        serializer=self.serializer_class(data=request.data) 
        serializer.is_valid(raise_exception=True)
        data=((serializer.validated_data)['access_token'])
        return Response(data,status=status.HTTP_200_OK)
    
    
# class GooglesigninViews(APIView):
#     serializer_class = GooglesigninSerializer

#     def post(self, request):
#         serializer = self.serializer_class(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         user_data = serializer.validated_data
        
#         # Assume register_social_user returns a token
#         token = register_social_user(user_data['provider'], user_data['email'], user_data['username'])
        
#         return Response({'token': token, 'user': user_data}, status=status.HTTP_200_OK)