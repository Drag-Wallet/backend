from rest_framework import serializers

from .models import *


class UserBankSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserBank
        exclude = ['is_deleted']
