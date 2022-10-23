from django.contrib import admin

from .models import *


# Register your models here.
@admin.register(UserBank)
class UserBankAdmin(admin.ModelAdmin):
    list_display = ['id', 'user']


@admin.register(KYC)
class KycAdmin(admin.ModelAdmin):
    list_display = ['id']
