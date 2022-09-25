from django.http import JsonResponse


def internal_server_error():
    return JsonResponse({"message": "Internal server error"}, status=500)


def required_fields_message(name):
    return JsonResponse({"message": f"{name} is required"}, status=400)


def return_message(message, status):
    return JsonResponse({"message": message}, status=status)
