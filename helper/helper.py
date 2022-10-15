import random

from django.http import JsonResponse


def internal_server_error(message="Internal server error"):
    return JsonResponse({"message": message}, status=500)


def required_fields_message(name):
    return JsonResponse({"message": f"{name} is required"}, status=400)


def return_message(message, status=200):
    return JsonResponse({"message": message}, status=status)


def check_auth_token(request):
    try:
        token = request.auth.user
        return token
    except Exception as e:
        print(e)
        return None


def generate_six_digit_otp():
    otp = str(''.join([str(random.randint(0, 999)).zfill(3) for _ in range(2)]))
    print("Your otp is here " + otp)
    return otp
