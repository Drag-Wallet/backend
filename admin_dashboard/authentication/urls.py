# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django.contrib.auth.views import LogoutView
from django.urls import path, include

from .views import login_view, register_user, home_view

urlpatterns = [
    path('', home_view, name="home"),
    path('dashboard/login/', login_view, name="login"),
    # path('register/', register_user, name="register"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path('social_login/', include('allauth.urls')),
]
