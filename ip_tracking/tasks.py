from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count
from .models import RequestLog, SuspiciousIP

@shared_task
def detect_suspicious_ips():
    """
    Analyzes RequestLog for the past hour to identify:
    1. High frequency (100+ requests/hour)
    2. Sensitive path probing (/admin, /login)
    """
    one_hour_ago = timezone.now() - timedelta(hours=1)
    
    # 1. Detect High Frequency Access
    high_freq_ips = (
        RequestLog.objects.filter(timestamp__gte=one_hour_ago)
        .values('ip_address')
        .annotate(request_count=Count('id'))
        .filter(request_count__gt=100)
    )

    for entry in high_freq_ips:
        SuspiciousIP.objects.get_or_create(
            ip_address=entry['ip_address'],
            reason=f"High frequency: {entry['request_count']} requests in 1 hour."
        )

    # 2. Detect Sensitive Path Probing
    sensitive_paths = ['/admin', '/login', '/wp-admin']
    probing_ips = (
        RequestLog.objects.filter(
            timestamp__gte=one_hour_ago,
            path__in=sensitive_paths
        )
        .values('ip_address')
        .distinct()
    )

    for entry in probing_ips:
        SuspiciousIP.objects.get_or_create(
            ip_address=entry['ip_address'],
            reason="Accessing sensitive paths."
        )

    return f"Processed anomalies. Flagged {len(high_freq_ips)} high-freq and {len(probing_ips)} probing IPs."