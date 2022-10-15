from drf_yasg.utils import swagger_auto_schema
from knox.auth import TokenAuthentication
from rest_framework import views
from rest_framework.permissions import IsAuthenticated

from auth_user.models import DragUser
from auth_user.serializers import *
from helper import *


class AddressView(views.APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    @swagger_auto_schema(tags=['address'])
    def get(self, request):
        try:
            user = check_auth_token(request)
            drag_user = DragUser.objects.get(user=user)
            address = Address.objects.filter(user=drag_user, is_deleted=False)
            address = AddressSerializer(address, context={'request': request}, many=True)
            return JsonResponse({"data": address.data})
        except Exception as e:
            print(e)
            return internal_server_error()

    @swagger_auto_schema(request_body=AddressSerializer, tags=['address'])
    def post(self, request):
        try:
            user = check_auth_token(request)

        except Exception as e:
            print(e)
            return internal_server_error()

    @swagger_auto_schema(request_body=AddressSerializer, tags=['address'])
    def put(self, request):
        try:
            user = check_auth_token(request)
        except Exception as e:
            print(e)
            return internal_server_error()

    @swagger_auto_schema(request_body=AddressSerializer, tags=['address'])
    def delete(self, request):
        try:
            user = check_auth_token(request)
        except Exception as e:
            print(e)
            return internal_server_error()
