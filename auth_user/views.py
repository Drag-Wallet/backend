import datetime
import random

import jwt
from decouple import config
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.db import transaction
from django.http import JsonResponse
from django.utils import timezone
from knox.auth import TokenAuthentication
from knox.models import AuthToken
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from auth_user.models import DragUser
from helper import required_fields_message, return_message, internal_server_error, check_auth_token


class RegisterUserView(APIView):

    @transaction.atomic
    def post(self, request):

        try:
            first_name = self.request.POST.get('first_name')
            if not first_name:
                return required_fields_message('first_name')

            last_name = self.request.POST.get('last_name')
            if not last_name:
                return required_fields_message('last_name')

            email = self.request.POST.get('email')
            if not email:
                return required_fields_message('email')

            email_exist = User.objects.filter(email=email).count()
            if email_exist:
                return return_message("Email already exist", 400)

            password = self.request.POST.get('password')
            if not password:
                return required_fields_message('password')
            new_user = User.objects.create(first_name=first_name, last_name=last_name, email=email, username=email)
            new_user.set_password(password)
            new_user.save()
            email_verify_otp_token = str(''.join([str(random.randint(0, 999)).zfill(3) for _ in range(2)]))
            email_verify_otp_token = jwt.encode(
                {"exp": datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(seconds=30),
                 "otp": email_verify_otp_token}, config('JWT_SECRET'))
            drag_user = DragUser.objects.create(user=new_user, email_verify_otp_token=email_verify_otp_token)
            return return_message("User added successfully", 200)
        except Exception as e:
            print(e)
            return internal_server_error()


class LoginUserView(APIView):
    def post(self, request):
        try:
            email = self.request.POST.get('email')
            if not email:
                return required_fields_message('email')

            password = self.request.POST.get('password')
            if not password:
                return required_fields_message('password')

            user_exist = User.objects.get(email=email)
            if not user_exist:
                return return_message("Invalid email", 400)

            drag_user = DragUser.objects.get(user=user_exist)

            if not drag_user:
                return return_message("User doesn't exist", 404)

            valid_credentials = authenticate(username=user_exist, password=password)

            if valid_credentials is None:
                return return_message("Invalid email and password", 400)

            if not drag_user.user.is_active:
                return return_message("Your account is disabled, please contact", 400)

            if not drag_user.email_verify_otp_token:
                data = {"id": drag_user.id, "first_name": user_exist.first_name,
                        "last_name": user_exist.last_name,
                        "email": email, "is_active": user_exist.is_active,
                        "token": AuthToken.objects.create(user_exist)[1]}
                return JsonResponse({"message": data})
            else:
                try:
                    jwt.decode(drag_user.verify_otp, config("JWT_SECRET"), algorithms=["HS256"])
                except:
                    drag_user.verify_otp = jwt.encode(
                        {"exp": datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(seconds=600),
                         "otp": str(''.join([str(random.randint(0, 999)).zfill(3) for _ in range(2)]))},
                        config('JWT_SECRET'))
                    drag_user.save()
                return return_message("Your account is not activated", 400)

        except Exception as e:
            print(e)
            return internal_server_error(e)


class VerifyAccount(APIView):
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
                decode_data = jwt.decode(drag_user.verify_otp, config("JWT_SECRET"), algorithms=["HS256"])
                if decode_data['otp'] == otp:
                    return return_message("Invalid otp", 400)
                drag_user.verify_otp = None
                drag_user.save()
                return return_message("account activated", 200)

            except Exception as e:
                print(e)
                return return_message("otp expired", 400)
        except Exception as e:
            return internal_server_error(e)


class ResendOtp(APIView):
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
                jwt.decode(user_exist.verify_otp, config("JWT_SECRET"), algorithms=["HS256"])
                return return_message("otp sent successfully", 200)
            except:
                drag_user.verify_otp = jwt.encode(
                    {"exp": datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(seconds=600),
                     "otp": str(''.join([str(random.randint(0, 999)).zfill(3) for _ in range(2)]))},
                    config('JWT_SECRET'))
                drag_user.save()
                return return_message("otp sent", 200)

        except Exception as e:
            print(e)
            return internal_server_error(e)


class ForgetPasswordView(APIView):
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
                    {"exp": datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(seconds=600),
                     "otp": str(''.join([str(random.randint(0, 999)).zfill(3) for _ in range(2)]))},
                    config('FORGET_JWT_SECRET'))
                drag_user.save()
                return return_message("otp sent", 200)
            except Exception as e:
                return return_message(e, 400)

        except Exception as e:
            return internal_server_error(e)


class ResetPassword(APIView):
    def post(self, request):
        try:
            pass
        except:
            return internal_server_error()


class ChangePassword(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            user = check_auth_token(request)
            print(user)
            return return_message("hi", 200)
        except:
            return internal_server_error()


class ChangeEmail(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            user = check_auth_token(request)
            new_email = self.request.POST.get('email')
            if not new_email:
                return required_fields_message("email")

            user_exist = DragUser.objects.get(user__email=new_email)
            if user_exist:
                return return_message("email is already in user", 400)


        except Exception as e:
            print(e)
            return internal_server_error()


class VerifyNewEmail(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            user = check_auth_token(request)
        except Exception as e:
            print(e)
            return internal_server_error()
