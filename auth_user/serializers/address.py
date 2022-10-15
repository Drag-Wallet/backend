from rest_framework import serializers

from auth_user.models import Address


class AddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = Address
        exclude = ['is_deleted']
