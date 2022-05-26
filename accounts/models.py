from django.db import models

from django.contrib.auth.models import AbractUser
from django.conf import settings


User=settings.AUTH_USER_MODEL

class User(AbractUser):
    is_staff=models.BooleanField(default=False)
    username=models.CharField(max_length=20,unique=True)
    email=models.EmailField(max_length=254,unique=True)
    phone_no=models.CharField(max_length=12,unique=True)
    is_customer=models.BooleanField(default=False)
    is_staff=models.BooleanField(default=False)
    is_superuser=models.BooleanField(default=False)
    is_active=models.BooleanField(default=False)
    is_admin=models.BooleanField(default=False)

    def __str__(self):
        return self.username




