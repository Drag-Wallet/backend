from django.contrib import admin


# Register your models here.
class UserAdmin(admin.ModelAdmin):
    list_display = ['id']
