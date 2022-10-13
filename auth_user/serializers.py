from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from rest_framework import serializers
from rest_framework.validators import UniqueValidator


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
    email = serializers.CharField(required=True)
    password = serializers.CharField(
        label='password',
        write_only=True,
        trim_whitespace=False
    )

    def validators(self, data):
        email = data.get('email')
        password = data.get('password')
        user = authenticate(requests=self.context.get('request'), email=email, password=password)
        print(user)
        if user is None:
            raise serializers.ValidationError("email or password is invalid")
        if user.is_active:
            raise serializers.ValidationError("account is disabled please contact admin")
        data['user'] = user
        return user
