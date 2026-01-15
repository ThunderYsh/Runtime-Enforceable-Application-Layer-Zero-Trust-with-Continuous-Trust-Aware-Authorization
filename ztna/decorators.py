from django.http import HttpResponseForbidden
from functools import wraps

def developer_only(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        # allow only superusers
        if not request.user.is_superuser:
            return HttpResponseForbidden(
                "<h1 style='color:red; text-align:center; margin-top:50px;'>"
                "🚫 Access Denied: Developer access only.</h1>"
            )
        return view_func(request, *args, **kwargs)
    return wrapper
