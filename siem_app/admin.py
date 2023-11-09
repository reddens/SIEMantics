from django.contrib import admin
from .models import ScanResults, LogEntry, SecurityResults, CrawlHistory

@admin.register(ScanResults)
class ScanResultsAdmin(admin.ModelAdmin):
    list_display = ['website_url', 'scan_output']

@admin.register(LogEntry)
class LogEntryAdmin(admin.ModelAdmin):
    list_display = ['log_text', 'log_path', 'accuracy', 'created_at']

@admin.register(SecurityResults)
class SecurityResultsAdmin(admin.ModelAdmin):
    list_display = ['command_name', 'result', 'status']

@admin.register(CrawlHistory)
class CrawlHistoryAdmin(admin.ModelAdmin):
    list_display = ['crawl_results', 'crawled_url']
