import uuid

from django.utils import timezone
from django.contrib.auth.models import User
from django.db import models


# Create your models here.
class DragUser(models.Model):
    id = models.CharField(max_length=256, default=uuid.uuid4().hex, editable=False, primary_key=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    email_verify_otp_token = models.CharField(max_length=256, null=True, blank=True)
    forget_password_otp_token = models.CharField(max_length=256, null=True, blank=True)
    change_user_email = models.CharField(max_length=256, null=True, blank=True)
    avatar = models.ImageField(upload_to='user_avatar', null=True, blank=True)

    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(auto_now=True, null=True, blank=True)
