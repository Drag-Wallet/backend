import uuid

from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone


# Create your models here.
class DragUser(models.Model):
    id = models.CharField(max_length=100, editable=False, primary_key=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    email_verify_otp_token = models.CharField(max_length=256, null=True, blank=True)
    forget_password_otp_token = models.CharField(max_length=256, null=True, blank=True)
    change_user_email_otp_token = models.CharField(max_length=256, null=True, blank=True)
    avatar = models.ImageField(upload_to='user_avatar', null=True, blank=True)

    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(auto_now=True, null=True, blank=True)


class Address(models.Model):
    id = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True)
    user = models.ForeignKey(DragUser, on_delete=models.CASCADE)
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    street = models.CharField(max_length=50)
    street2 = models.CharField(max_length=50, null=True, blank=True)
    city = models.CharField(max_length=50)
    state = models.CharField(max_length=50)
    zip = models.CharField(max_length=6)
    country = models.CharField(max_length=50)
    phone = models.CharField(max_length=10)
    email = models.CharField(max_length=50)
    is_deleted = models.BooleanField(default=False)

    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(auto_now=True, null=True, blank=True)
