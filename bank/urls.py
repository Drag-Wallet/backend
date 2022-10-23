from django.urls import path

from .views import *

urlpatterns = [
    path('user_bank/', UseBankView.as_view())
]
