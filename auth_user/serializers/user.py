from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from helper.serializer_helper import required


class UserRegistrationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(validators=[UniqueValidator(queryset=User.objects.all())])
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def save(self, **kwargs):
        user = User(email=self.validated_data['email'], username=self.validated_data['email'],
                    first_name=self.validated_data['first_name'],
                    last_name=self.validated_data['last_name'],
                    is_active=True)
        password = self.validated_data['password']
        user.set_password(password)
        user.save()
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(validators=[required])
    password = serializers.CharField(
        label='password',
        write_only=True,
        trim_whitespace=False
    )

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')
        user = authenticate(requests=self.context.get('request'), username=email, password=password)
        if user is None:
            raise serializers.ValidationError("email or password is invalid", 401)
        if not user.is_active:
            raise serializers.ValidationError("account is disabled please contact admin", 401)
        data['user'] = user
        return data


class VerifyAccountSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6, min_length=6, required=True)

    class Meta:
        fields = ['email', 'otp']


class EmailSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    class Meta:
        fields = ['email']


class ResetPasswordSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=256, required=True)

    class Meta:
        fields = ['token', ]


class ChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    class Meta:
        fields = ['password', 'new_password']

class OtpFieldSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6, min_length=6)
