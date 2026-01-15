from django.http import JsonResponse
from ratelimit.decorators import ratelimit

@ratelimit(key='user_or_ip', rate='5/m', block=True)
def sensitive_login_view(request):
    """
    A sensitive view protected by rate limiting.
    Anonymous: 5 requests per minute
    Authenticated: 10 requests per minute
    """
    # Logic to handle different rates for auth vs anon
    was_limited = getattr(request, 'limited', False)
    
    # If the user is authenticated, we allow a higher threshold 
    # defined by a second decorator or logic check
    if request.user.is_authenticated:
        # Re-evaluating for auth users (10/m)
        @ratelimit(key='user', rate='10/m', block=True)
        def auth_check(request):
            return JsonResponse({"message": "Authenticated access successful"})
        return auth_check(request)

    return JsonResponse({"message": "Anonymous access successful"})

def ratelimit_error(request, exception):
    """Custom view for when a user hits the limit."""
    return JsonResponse(
        {"error": "Too many requests. Please slow down."}, 
        status=429
    )

@ratelimit(key='ip', rate='5/m', block=True)  # Limit for everyone by IP
@ratelimit(key='user', rate='10/m', block=True) # Higher limit for logged in users
def login_view(request):
    return JsonResponse({"status": "OK"})