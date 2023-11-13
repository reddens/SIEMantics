# yourapp/celery.py
from __future__ import absolute_import, unicode_literals
import os
from celery import Celery

# set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'siem_app.settings')

# create a Celery instance and configure it using the settings from Django.
app = Celery('siem_app')

# namespace='CELERY' means all Celery-related configuration keys should have a 'CELERY_' prefix.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django app configs.
app.autodiscover_tasks()