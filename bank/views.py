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

