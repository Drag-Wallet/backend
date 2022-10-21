from django.urls import path

from bank.views import BankList

urlpatterns = [
    path('add/', BankList.as_view())
]
