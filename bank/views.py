from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from knox.auth import TokenAuthentication
from rest_framework import views
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import IsAuthenticated

from helper import *
from .serializer import *


# Create your views here.
class UseBankView(views.APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    parser_classes = (MultiPartParser,)
    id = openapi.Parameter(
        'id', in_=openapi.IN_QUERY, description='id', type=openapi.TYPE_STRING, required=True)

    @swagger_auto_schema(tags=['user_bank'])
    def get(self, request):
        try:
            user = check_auth_token(request)
            drag_user = DragUser.objects.get(user=user)
            users_bank = UserBank.objects.filter(user=drag_user)
            users_bank_serialized_data = UserBankSerializer(users_bank, context={'request': request}, many=True)
            return JsonResponse({"data": users_bank_serialized_data.data})
        except Exception as e:
            return internal_server_error()

    @swagger_auto_schema(tags=['user_bank'], request_body=UserBankSerializer)
    def post(self, request):
        try:
            user = check_auth_token(request)
            user_bank = UserBankSerializer(data=request.data, context={'request': request})
            if user_bank.is_valid():
                drag_user = DragUser.objects.get(user=user)
                users_data = get_values_from_request(request)
                UserBank.objects.create(user=drag_user, **users_data)
            return JsonResponse(user_bank.errors, safe=False, status=400)

        except Exception as e:
            print(e)
            return internal_server_error()

    @swagger_auto_schema(tags=['user_bank'], request_body=UserBankSerializer, manual_parameters=[id])
    def put(self, request):
        try:
            user = check_auth_token(request)
            id = self.request.GET.get('id')
            if not id:
                return required_fields_message('id')
            user_bank = UserBankSerializer(data=request.data, context={'request': request})
            if user_bank.is_valid():
                drag_user = DragUser.objects.get(user=user)
                user_data = get_values_from_request(request)
                user_bank_update = UserBank.objects.update(user=drag_user, **user_data, id=id)
                if user_bank_update:
                    return return_message("User bank updated")
                return return_message("Invalid address", 400)
            return JsonResponse(user_bank.errors, safe=False, statsu=400)
        except Exception as e:
            print(e)
            return internal_server_error()

    @swagger_auto_schema(tags=['user_bank'], manual_parameters=[id])
    def delete(self, request):
        try:
            user = check_auth_token(request)
            id = self.request.GET.get('id')
            if not id:
                return required_fields_message('id')
            drag_user = DragUser.objects.get(user=user)
            user_bank = UserBank.objects.get(user=drag_user, id=id)
            if user_bank:
                user_bank.is_deleted = True
                user_bank.save()
                return return_message("bank deleted")
            return return_message("invalid bank ", 400)
        except Exception as e:
            print(e)
            return internal_server_error()
