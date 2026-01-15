from .models import RequestLog

class IPTrackingMiddleware:
    def __init__ (self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')

        RequestLog.objects.create(ip_address=ip, path=request.path)
        return self.get_response(request)