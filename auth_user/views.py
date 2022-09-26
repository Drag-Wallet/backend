import json
import random

from django.contrib.auth.models import User
from django.http import JsonResponse
from rest_framework.views import APIView

from auth_user.models import DragUser
from auth_user.serializers import DragUserSerializer
from helper import required_fields_message, return_message, internal_server_error


class RegisterUserView(APIView):
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

            verify_otp = str(''.join([str(random.randint(0, 999)).zfill(3) for _ in range(2)]))
            drag_user = DragUser.objects.create(user=new_user, verify_otp=verify_otp)
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

            email_exist = User.objects.get(email=email)
            if email_exist:
                drag_user = DragUser.objects.get(user=email_exist)
                print(DragUserSerializer(drag_user).data)
                return JsonResponse({"message": DragUserSerializer(drag_user).data})
            else:
                return return_message("Invalid email and password", 400)


        except Exception as e:
            print(e)
            return internal_server_error(e)


class VerifyAccount(APIView):
    def post(self, request):
        try:
            pass
        except:
            return internal_server_error()


class ForgetPasswordView(APIView):
    def post(self, request):
        try:
            pass
        except:
            return internal_server_error()


class ResetPassword(APIView):
    def post(self, request):
        try:
            pass
        except:
            return internal_server_error()


class ChangePassword(APIView):
    def post(self, request):
        try:
            pass
        except:
            return internal_server_error()


class ChangeEmail(APIView):
    def post(self, request):
        try:
            pass
        except:
            return internal_server_error()
