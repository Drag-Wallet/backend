from django.urls import path

from auth_user.views import *

urlpatterns = [
    path('register/', RegisterUserView.as_view(), name="register"),
    path('verify_account/', VerifyAccount.as_view(), name="verify_account"),
    path('resend_verify_otp/', ResendVerifyOtp.as_view(), name="resend_verify_otp"),
    path('login/', LoginUserView.as_view(), name="login"),
    path('change_password/', ChangePassword.as_view(), name="change_password"),
    path('change_email/', ChangeEmail.as_view(), name="change_email"),
    path('verify_new_email/', VerifyNewEmail.as_view(), name="verify_new_email"),
    path('resend_new_email_otp/', ResendNewEmailOtp.as_view(), name="resend_new_email_otp"),
    path('forget_password/', ForgetPasswordView.as_view(), name="forget_password"),
    path('reset_password/', ResetPassword.as_view(), name="reset_password")
]
