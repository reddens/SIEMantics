from django.shortcuts import render
from .models import ScanResults, LogEntry, SecurityResults, CrawlHistory
from .scripts import scan_website, crawl_website, run_log_analysis, run_sca_benchmark, crawl_system_for_logs, analyse_logs, train_and_evaluate_classifier, extract_relevant_data, get_cve_info

def index(request):
    # Retrieve the latest objects from each model
    latest_scan_result = ScanResults.objects.last()
    latest_crawl_result = CrawlHistory.objects.last()
    latest_log_entry = LogEntry.objects.last()
    latest_security_result = SecurityResults.objects.last()
    latest_log_entries = LogEntry.objects.order_by('-created_at')[:2]

    return render(request, 'siem_app/index.html', {
        'scan_output': latest_scan_result.scan_output if latest_scan_result else None,
        'crawl_results': latest_crawl_result.crawled_website if latest_crawl_result else None,
        'log_entries': latest_log_entries if latest_log_entries else None,
        'accuracy': latest_log_entry.accuracy if latest_log_entry else None, 
        'security_results': latest_security_result.result if latest_security_result else None,
    })
    
def scan_website_view(request):
    website_url = request.POST.get('website_url')
    scan_output = scan_website(website_url)

    # Save scan result to the database
    ScanResults.objects.create(website_url=website_url, scan_output=scan_output)

    return render(request, 'siem_app/scan_result.html', {'scan_output': scan_output})

def crawl_website_view(request):
    url = request.POST.get('url')
    crawl_results = crawl_website(url)
    # Save crawl results to the database (if needed)
    CrawlResults.objects.create(crawled_website=url)

    return render(request, 'siem_app/crawl_result.html', {'crawl_results': crawl_results})


def analyse_logs_view(request):
    result = run_log_analysis()

    if result['suspicious_entries']:
        for log_entry_data in result['suspicious_entries']:
            log_entry = LogEntry.objects.create(
                log_text=log_entry_data['log_entry'],
                log_path=log_entry_data['path'],
                accuracy=log_entry_data['accuracy']
            )
            print("Saved suspicious log data to the database.")
    else:
        print("No suspicious logs found.")

    # Retrieve the latest N log entries
    latest_log_entries = LogEntry.objects.order_by('-created_at')[:2]  # Change 5 to the desired number

    # Pass the results to the template or return a response as needed
    return render(request, 'siem_app/index.html', {
        'log_entries': latest_log_entries,
    })
