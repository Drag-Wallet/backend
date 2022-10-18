from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from knox.auth import TokenAuthentication
from rest_framework import views
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import IsAuthenticated

from auth_user.models import DragUser
from auth_user.serializers import *
from helper import *


class AddressView(views.APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    parser_classes = (MultiPartParser,)
    id = openapi.Parameter(
        'id', in_=openapi.IN_QUERY, description='id', type=openapi.TYPE_STRING)

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
            address = AddressSerializer(data=request.data, context={'request': request})
            if address.is_valid():
                drag_user = DragUser.objects.get(user=user)
                user_data = {x: request.data[x] for x in request.data.keys()}
                Address.objects.create(user=drag_user, **user_data)
                return return_message("hi")

            return JsonResponse(address.errors, safe=False, status=400)

        except Exception as e:
            print(e)
            return internal_server_error()

    @swagger_auto_schema(request_body=AddressSerializer, tags=['address'], manual_parameters=[id])
    def put(self, request):
        try:
            user = check_auth_token(request)
            id = self.request.GET.get('id')
            address = AddressSerializer(data=request.data, context={'request': request})
            if address.is_valid():
                drag_user = DragUser.objects.get(user=user)
                user_data = {x: request.data[x] for x in request.data.keys()}
                print(request.data['first_name'])
                print(user_data)
                address_updated = Address.objects.update(user=drag_user, **user_data, id=id)
                if address_updated is 1:
                    return return_message("address updated")
                return return_message("Invalid address", 400)
            return JsonResponse(address.errors, safe=False, status=400)

        except Exception as e:
            print(e)
            return internal_server_error()

    @swagger_auto_schema(tags=['address'], manual_parameters=[id])
    def delete(self, request):
        try:
            user = check_auth_token(request)
            id = self.request.GET.get('id')
            if not id:
                return required_fields_message("id")
            drag_user = DragUser.objects.get(user=user)
            address = Address.objects.get(user=drag_user, id=id)
            if not address:
                return return_message("invalid address id")
            address.is_deleted = True
            address.save()
            return return_message("address deleted")
        except Exception as e:
            print(e)
            return internal_server_error()
