import subprocess
import concurrent.futures
from django.http import JsonResponse
from django.shortcuts import render
from .models import ScanResults, LogEntry, SecurityResults, CrawlHistory
from .scripts import scan_website, crawl_website, run_log_analysis, run_sca_benchmark, crawl_system_for_logs, analyse_logs, train_and_evaluate_classifier, extract_relevant_data, get_cve_info, security_comms
from celery import shared_task
from django.core.serializers import serialize
from concurrent.futures import ThreadPoolExecutor


def index(request):
    # Retrieve the latest objects from each model
    latest_scan_result = ScanResults.objects.last()
    latest_crawl_result = CrawlHistory.objects.last()
    latest_log_entry = LogEntry.objects.last()
    latest_security_result = SecurityResults.objects.last()
    latest_log_entries = LogEntry.objects.order_by('-created_at')[:2]

    return render(request, 'siem_app/index.html', {
        'scan_output': latest_scan_result.scan_output if latest_scan_result else None,
        'crawl_results': latest_crawl_result.crawl_results if latest_crawl_result else None,
        'crawled_url': latest_crawl_result.crawled_url if latest_crawl_result else None,
        'log_entries': latest_log_entries if latest_log_entries else None,
        'accuracy': latest_log_entry.accuracy if latest_log_entry else None, 
        'security_results': latest_security_result.result if latest_security_result else None,
    })
    
def scan_website_view(request):
    website_url = request.POST.get('website_url')

    # Increase the number of threads if needed
    with ThreadPoolExecutor(max_workers=5) as executor:
        future = executor.submit(scan_website, website_url)
        try:
            scan_output = future.result()
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    ScanResults.objects.create(website_url=website_url, scan_output=scan_output)

    return JsonResponse({'scan_output': scan_output})


def crawl_website_view(request):
    url = request.POST.get('crawl_website_url')

    # Using ThreadPoolExecutor to run crawl_website asynchronously
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future = executor.submit(crawl_website, url)
        results_list = future.result()

    crawl_results = '\n'.join(results_list)

    # Save crawl results to the database (if needed)
    CrawlHistory.objects.create(crawled_url=url, crawl_results=crawl_results)

    return JsonResponse({'crawl_results': crawl_results, 'crawled_url': url})

def analyse_logs_view(request):
    # Using ThreadPoolExecutor to run run_log_analysis asynchronously
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future = executor.submit(run_log_analysis)
        result = future.result()

    if result['suspicious_entries']:
        log_entries = []
        for log_entry_data in result['suspicious_entries']:
            log_entry = LogEntry.objects.create(
                log_text=log_entry_data['log_entry'],
                log_path=log_entry_data['path'],
                accuracy=log_entry_data['accuracy']
            )
            log_entries.append({
                'log_text': log_entry.log_text,
                'log_path': log_entry.log_path,
                'accuracy': log_entry.accuracy,
            })
            print("Saved suspicious log data to the database.")
    else:
        print("No suspicious logs found.")

    # Retrieve the latest N log entries
    latest_log_entries = LogEntry.objects.order_by('-created_at')[:2].values()

    # Convert QuerySet to a list of dictionaries
    latest_log_entries = list(latest_log_entries)

    # Pass the results to the template or return a response as needed
    return JsonResponse({
        'log_entries': latest_log_entries,
    })

def sca_benchmark_view(request):
    # Using ThreadPoolExecutor to run run_sca_benchmark asynchronously
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future = executor.submit(run_sca_benchmark)
        list_of_issues = future.result()

    joined_list = '\n'.join(list_of_issues)

    SecurityResults.objects.create(result=joined_list)

    security_results = SecurityResults.objects.last().result
    return JsonResponse({'security_results': security_results})