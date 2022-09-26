from django.urls import path
from auth_user.views import *

urlpatterns = [
    path('register/', RegisterUserView.as_view()),
    path('verify_account', VerifyAccount.as_view()),
    path('login/', LoginUserView.as_view()),
    path('change-password', ChangePassword.as_view()),
]
