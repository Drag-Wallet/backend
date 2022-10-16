from rest_framework import serializers


def required(value):
    if value is None:
        raise serializers.ValidationError("required field")
