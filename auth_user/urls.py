from django.urls import path
from auth_user.views import *

urlpatterns = [
    path('register/', RegisterUserView.as_view()),
    path('verify_account/', VerifyAccount.as_view()),
    path('resend_verify_otp/', ResendOtp.as_view()),
    path('login/', LoginUserView.as_view()),
    path('change_password/', ChangePassword.as_view()),
]
