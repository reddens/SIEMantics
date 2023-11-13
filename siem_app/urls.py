# siem_app/urls.py

from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('scan_website/', views.scan_website_view, name='scan_website'),
    path('crawl_website/', views.crawl_website_view, name='crawl_website'),
    path('analyse_logs/', views.analyse_logs_view, name='analyse_logs'),
    path('get_score/', views.sca_benchmark_view, name='get_score'),
]