from django.urls import path
from .views import RegisterViews,Verifyemail,LoginUser,TestauthenicatedView,Restpasswordsend,GooglesigninViews,SocialSignInView


urlpatterns = [
    path('register/',RegisterViews.as_view(),name='register'),
    path('varify-email/',Verifyemail.as_view(),name='varify-email'),
    path('login/',LoginUser.as_view(),name='login'),
    path('profile/',TestauthenicatedView.as_view(),name='profile'),
    path('reset-password/',Restpasswordsend.as_view(),name='reset-password'),
    path('google/',GooglesigninViews.as_view(),name='google'),
    path('signin/',SocialSignInView.as_view(),name='signin')
]
