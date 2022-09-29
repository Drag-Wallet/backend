from django.contrib.auth.models import User
from rest_framework import serializers

from auth_user.models import DragUser


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'


class DragUserSerializer(serializers.ModelSerializer):
    user = UserSerializer()

    class Meta:
        model = DragUser
        fields = '__all__'
