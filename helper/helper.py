from django.http import JsonResponse


def internal_server_error(message="Internal server error"):
    return JsonResponse({"message": message}, status=500)


def required_fields_message(name):
    return JsonResponse({"message": f"{name} is required"}, status=400)


def return_message(message, status):
    return JsonResponse({"message": message}, status=status)
