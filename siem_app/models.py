from django.db import models

# Create your models here.
from django.db import models 

class ScanResults(models.Model): 
    website_url = models.URLField()
    scan_output = models.TextField()

class LogEntry(models.Model):
    log_text = models.TextField(null=True)
    log_path = models.TextField(max_length=255,null=True)
    accuracy = models.TextField(null=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)  # Automatically set to the current date and time on creation

class SecurityResults(models.Model):
    command_name = models.CharField(max_length=255)
    result = models.TextField()
    status = models.CharField(max_length=10)

class CrawlHistory(models.Model):
    crawl_results = models.TextField(null=True)
    crawled_url = models.URLField(null=True)