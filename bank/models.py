import uuid

from django.db import models

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
    id = models.CharField(default=uuid.uuid4, primary_key=True, editable=False)
    account_holder_name = models.CharField(max_length=50)
    account_number = models.CharField(max_length=25)
    account_type = models.CharField(choices=BANK_ACCOUNT_TYPE_CHOICE)
    routing_number = models.CharField(max_length=9)
    user = models.ForeignKey(DragUser, on_delete=models.CASCADE)


class KYC(models.Model):
    verification_type = models.CharField(choices=KYC_TYPE_CHOICE)
    status = models.CharField(choices=STATUS_CHOICE)
    document = models.ImageField(upload_to='kyc')
