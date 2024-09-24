from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken

class UserManager(BaseUserManager):
    def email_validated(self, email):
        try:
            validate_email(email)
        except ValidationError:
            raise ValidationError('Please enter a valid email')
    def create_user(self, email, username, password,**extra_fields):
        if not email:
            raise ValidationError('An email is required')

        if not username:
            raise ValueError('Please enter a username')

        user = self.model(email=email,username=username,**extra_fields)

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, password=None):
        user = self.create_user(
            email,
            password=password,
            username=username,
        )
        user.is_admin = True
        user.is_varify = True
        user.save(using=self._db)
        return user
    
    
AUTH_PROVIDERS={'microsoft':'microsoft','email': 'email','google':'google'} 


  
class MyUser(AbstractBaseUser):
    email = models.EmailField(
            verbose_name="email address",
            max_length=255,
            unique=True,
        )
    username=models.CharField(max_length=250)
    is_varify = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    auth_provider=models.CharField(max_length=50,default=AUTH_PROVIDERS.get('email'),null=True)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]
    
    def __str__(self):
        return self.email
    
    @property
    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)  # Corrected 'acess' to 'access'
        }
         
    
    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, app_label):
        return self.is_admin
    
    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_admin
    
    
class Onetimepassword(models.Model):
    user=models.OneToOneField(MyUser,on_delete=models.CASCADE)
    code=models.CharField(max_length=6,unique=True)
    
    def __str__(self) -> str:
        return self.user