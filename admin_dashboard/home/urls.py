# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django.urls import path, re_path
from admin_dashboard.home import views

urlpatterns = [

    # The home page
    path('dashboard/', views.index, name='home'),

    # Matches any html file
    re_path(r'^dashboard/.*\.*', views.pages, name='pages'),
]
