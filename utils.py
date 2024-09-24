import random

from django.core.mail import EmailMessage
from .models import MyUser,Onetimepassword
from django.conf import settings

def generateotp():
    otp=""
    for i in  range(6):
        otp+=str(random.randint(1,9))
    return otp

def send_code_to_user(email):
    Subject='one time passcode for Email verifications'
    otp_code=generateotp()
    print(otp_code)
    user=MyUser.objects.get(email=email)
    current_site='myauth.com'
    email_body='hi thank you for sign in and verifing'
    from_email=settings.DEFAULT_FROM_EMAIL
    Onetimepassword.objects.create(user=user,code=otp_code)
    send_email=EmailMessage(Subject,current_site,email_body,from_email)
    send_email.send(fail_silently=True)
    
def send_normal_email(data):
    email=EmailMessage(
    subject=data['email_subject'],
    body=data['email_body'],
    from_email=settings.EMAIL.HOST.USER,
    to=[data['to_email']])
    email.send()