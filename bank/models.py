import uuid

from django.db import models
from django.utils import timezone

from auth_user.models import DragUser

BANK_ACCOUNT_TYPE_CHOICE = (
    ('checking', 'checking'),
    ('savings', 'savings')
)

KYC_TYPE_CHOICE = (
    ('Personal', 'Personal'),
    ('Address', 'Address'),
    ('Account', 'Account')
)

STATUS_CHOICE = (
    ('Verified', 'Verified'),
    ('Not verified', 'Not verified')
)


# Create your models here.
class UserBank(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    account_holder_name = models.CharField(max_length=50)
    account_number = models.CharField(max_length=25)
    account_type = models.CharField(choices=BANK_ACCOUNT_TYPE_CHOICE, max_length=10)
    routing_number = models.CharField(max_length=9)
    user = models.ForeignKey(DragUser, on_delete=models.CASCADE)
    is_deleted = models.BooleanField(default=0)

    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(auto_now=True, null=True, blank=True)


class KYC(models.Model):
    verification_type = models.CharField(choices=KYC_TYPE_CHOICE, max_length=15)
    status = models.CharField(choices=STATUS_CHOICE, max_length=18)
    document = models.ImageField(upload_to='kyc')
    is_deleted = models.BooleanField(default=0)

    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(auto_now=True, null=True, blank=True)
