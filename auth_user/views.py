import datetime

import jwt
from decouple import config
from django.http import JsonResponse
from django.utils import timezone
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from knox.auth import TokenAuthentication
from knox.models import AuthToken
from rest_framework import status, views
from rest_framework.permissions import IsAuthenticated

from auth_user.models import DragUser
from helper import required_fields_message, return_message, internal_server_error, check_auth_token, \
    generate_six_digit_otp
from .serializers import *


class RegisterUserView(views.APIView):
    @swagger_auto_schema(request_body=UserRegistrationSerializer, tags=['auth'])
    def post(self, request):
        try:
            serializer = UserRegistrationSerializer(data=request.data, context={'request': request})
            if serializer.is_valid():
                new_user = serializer.save()
                email_verify_otp_token = jwt.encode(
                    {"exp": datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(minutes=10),
                     "otp": generate_six_digit_otp()}, config('JWT_SECRET'))
                drag_user = DragUser.objects.create(user=new_user, email_verify_otp_token=email_verify_otp_token)
                return return_message("User added successfully", 200)
            return JsonResponse(serializer.errors, safe=False, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print(e)
            return internal_server_error()


class LoginUserView(views.APIView):
    @swagger_auto_schema(request_body=LoginSerializer, tags=['auth'])
    def post(self, request):
        try:
            serializer = LoginSerializer(data=request.data, context={'request': request})
            serializer.is_valid(raise_exception=True)
            user_exist = serializer.validated_data['user']
            drag_user = DragUser.objects.get(user=user_exist)
            if not drag_user.email_verify_otp_token:
                data = {"id": drag_user.id, "first_name": drag_user.user.first_name,
                        "last_name": drag_user.user.last_name,
                        "email": drag_user.user.email,
                        "token": AuthToken.objects.create(drag_user.user)[1]}
                return JsonResponse({"message": data})
            else:
                try:
                    jwt.decode(drag_user.email_verify_otp_token, config("JWT_SECRET"), algorithms=["HS256"])
                except:
                    drag_user.email_verify_otp_token = jwt.encode(
                        {"exp": datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(minutes=10),
                         "otp": generate_six_digit_otp()},
                        config('JWT_SECRET'))
                    drag_user.save()
                return return_message("Your account is not activated", 400)
        except serializers.ValidationError as ve:
            return return_message(ve.__dict__['detail']['non_field_errors'][0].title(), 200)
        except Exception as e:
            print(e)
            return internal_server_error()


class VerifyAccount(views.APIView):
    @swagger_auto_schema(request_body=VerifyAccountSerializer, tags=['auth'])
    def post(self, request):
        try:
            email = self.request.POST.get('email')
            if not email:
                return required_fields_message('email')

            otp = self.request.POST.get('otp')
            if not otp:
                return required_fields_message('otp')

            user_exist = User.objects.get(email=email)
            if not user_exist:
                return return_message("Invalid email", 404)

            drag_user = DragUser.objects.get(user=user_exist)

            if not drag_user:
                return return_message("User doesn't exist", 404)

            try:
                decode_data = jwt.decode(drag_user.email_verify_otp_token, config("JWT_SECRET"), algorithms=["HS256"])
                if decode_data['otp'] != otp:
                    return return_message("Invalid otp", 400)
                drag_user.email_verify_otp_token = None
                drag_user.save()
                return return_message("account activated", 200)

            except Exception as e:
                print(e)
                return return_message("otp expired", 400)
        except Exception as e:
            return internal_server_error(e)


class ResendVerifyOtp(views.APIView):
    @swagger_auto_schema(request_body=EmailSerializer, tags=['auth'])
    def post(self, request):
        try:
            email = self.request.POST.get('email')
            if not email:
                return required_fields_message('email')

            user_exist = User.objects.get(email=email)

            if not user_exist:
                return return_message("Invalid email", 404)

            drag_user = DragUser.objects.get(user=user_exist)
            if not drag_user:
                return return_message("User doesn't exist", 404)
            try:
                jwt.decode(user_exist.email_verify_otp_token, config("JWT_SECRET"), algorithms=["HS256"])
                return return_message("otp sent successfully", 200)
            except:
                drag_user.email_verify_otp_token = jwt.encode(
                    {"exp": datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(minutes=10),
                     "otp": generate_six_digit_otp()},
                    config('JWT_SECRET'))
                drag_user.save()
                return return_message("otp sent", 200)

        except Exception as e:
            print(e)
            return internal_server_error()


class ForgetPasswordView(views.APIView):
    @swagger_auto_schema(request_body=EmailSerializer, tags=['auth'])
    def post(self, request):
        try:
            email = self.request.POST.get('email')
            if not email:
                return return_message("email", 404)
            user_exist = User.objects.get(email=email)

            if not user_exist:
                return return_message("Invalid email", 404)

            drag_user = DragUser.objects.get(user=user_exist)
            if not drag_user:
                return return_message("User doesn't exist", 404)

            try:
                drag_user.forget_password_otp_token = jwt.encode(
                    {"exp": datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(minutes=10),
                     "message": "forget_account"},
                    config('FORGET_JWT_SECRET'))
                drag_user.save()
                return return_message("otp sent", 200)
            except Exception as e:
                return return_message(e, 400)

        except Exception as e:
            return internal_server_error(e)


class ResetPassword(views.APIView):
    password = openapi.Parameter(
        'password', in_=openapi.IN_QUERY, description='password', type=openapi.TYPE_STRING)

    @swagger_auto_schema(request_body=ResetPasswordSerializer, tags=['auth'], manual_parameters=[password])
    def post(self, request):
        try:
            token = self.request.POST.get('token')
            if not token:
                return required_fields_message("token")
            password = self.request.GET.get('password')
            drag_user = DragUser.objects.get(forget_password_otp_token=token)
            print(drag_user)
            if not drag_user:
                return return_message("invalid link", 400)
            try:
                jwt.decode(token, config['FORGET_JWT_SECRET'], algorithms=["HS256"])
                if not password:
                    return return_message("valid link")
                user = User.objects.get(email=drag_user.user.email)
                user.set_password(password)
                return return_message("password changed successfully")
            except Exception as e:
                return return_message("link expired", 404)

        except Exception as e:
            print(e)
            return internal_server_error()


class ChangePassword(views.APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    @swagger_auto_schema(request_body=ChangePasswordSerializer, tags=['auth'])
    def post(self, request):
        try:
            password = self.request.POST.get('password')
            if not password:
                return required_fields_message('password')
            new_password = self.request.POST.get('new_password')
            if not new_password:
                return required_fields_message('new_password')
            user = check_auth_token(request)
            user = authenticate(username=user.email, password=password)
            if not user:
                return return_message("invalid password")
            user.set_password(new_password)
            user.save()
            return return_message("password changed")
        except Exception as e:
            print(e)
            return internal_server_error()


class ChangeEmail(views.APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    @swagger_auto_schema(request_body=EmailSerializer, tags=['auth'])
    def post(self, request):
        try:
            user = check_auth_token(request)
            new_email = self.request.POST.get('email')
            if not new_email:
                return required_fields_message("email")

            user_exist = DragUser.objects.get(user__email=new_email)
            if user_exist:
                return return_message("email is already in use", 400)
            user.change_user_email_otp_token = jwt.encode(
                {"expiry": datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(minutes=10),
                 "email": new_email,
                 "otp": generate_six_digit_otp()},
                config('CHANGE_EMAIL_SECRET'))
            user.save()
            return return_message("otp sent")

        except Exception as e:
            print(e)
            return internal_server_error()


class ResendNewEmailOtp(views.APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    @swagger_auto_schema(tags=['auth'])
    def post(self, request):
        try:
            user = check_auth_token(request)
            drag_user = DragUser.objects.get(user=user)
            decode_data = jwt.decode(drag_user.change_user_email_otp_token, config('CHANGE_EMAIL_SECRET'))
            if decode_data['expiry'] < datetime.datetime.now(tz=timezone.utc):
                drag_user.change_user_email_otp_token = jwt.encode(
                    {"expiry": datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(minutes=10),
                     "email": decode_data.email,
                     "otp": generate_six_digit_otp()},
                    config('CHANGE_EMAIL_SECRET'))
            print(decode_data.otp)
            return return_message("otp sent", 200)
        except Exception as e:
            return internal_server_error()


class VerifyNewEmail(views.APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    @swagger_auto_schema(request_body=OtpFieldSerializer, tags=['auth'])
    def post(self, request):
        try:
            otp = self.request.POST.get('otp')
            if not otp:
                return required_fields_message('otp')
            user = check_auth_token(request)
            drag_user = DragUser.objects.get(user=user)
            try:
                decode_data = jwt.decode(drag_user.change_user_email_otp_token, config('CHANGE_EMAIL_SECRET'))
                if decode_data['expiry'] < datetime.datetime.now(tz=timezone.utc):
                    return return_message("otp expired", 400)
                if decode_data['otp'] != otp:
                    return return_message("invalid otp", 400)
                drag_user.user.email = decode_data['email']
                drag_user.change_user_email_otp_token = None
                drag_user.save()
                return return_message("email changed successfully")
            except Exception as e:
                print(e)
                return return_message("otp expired", 400)
        except Exception as e:
            print(e)
            return internal_server_error()
