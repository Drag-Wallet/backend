import os
from django.utils import timezone
from django.contrib.auth.models import User
from django.db import models
import jwt
import datetime


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
            {"exp": datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(seconds=600), "otp": self.verify_otp},
            os.environ.get('JWT_SECRET'),
        )
        super().save(**kwargs)
