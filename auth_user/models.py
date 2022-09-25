import os
from django.utils import timezone
from django.contrib.auth.models import User
from django.db import models
import jwt
from datetime import datetime


# Create your models here.
class DragUser(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    active_account = models.BooleanField(default=1)
    verify_otp = models.CharField(max_length=256, null=True, blank=True)
    avatar = models.ImageField(upload_to='user_avatar', null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(auto_now=True, null=True, blank=True)

    def save(self, **kwargs):
        self.verify_otp = jwt.encode(
            {"otp": self.verify_otp, "exp": datetime.now().microsecond + 10},
            os.environ.get('JWT_SECRET'), algorithm="HS256")
        print(self.verify_otp)
        super().save(**kwargs)
        print('hi')
