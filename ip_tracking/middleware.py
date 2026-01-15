import requests
from django.http import HttpResponseForbidden
from django.core.cache import cache
from .models import RequestLog, BlockedIP

class IPTrackingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # 1. Extract IP
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        ip = x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')

        # 2. Block Check
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Your IP has been blocked.")

        # 3. Geolocation Logic with 24-hour Cache
        cache_key = f"geo_{ip}"
        geo_data = cache.get(cache_key)

        if not geo_data:
            try:
                # Using ip-api.com (Free for non-commercial use)
                response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
                data = response.json()
                
                if data.get('status') == 'success':
                    geo_data = {
                        'country': data.get('country'),
                        'city': data.get('city')
                    }
                else:
                    geo_data = {'country': 'Unknown', 'city': 'Unknown'}
            except Exception:
                geo_data = {'country': 'Error', 'city': 'Error'}
            
            # Store result in cache for 24 hours (86400 seconds)
            cache.set(cache_key, geo_data, 86400)

        # 4. Log the request
        RequestLog.objects.create(
            ip_address=ip,
            path=request.path,
            country=geo_data.get('country'),
            city=geo_data.get('city')
        )

        return self.get_response(request)