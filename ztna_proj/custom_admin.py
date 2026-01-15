from django.contrib.admin import AdminSite

class ZTNAAdminSite(AdminSite):
    site_header = "ZTNA Admin"
    site_title = "ZTNA Admin"
    index_title = "ZTNA Secure Panel"

    def has_permission(self, request):
        return request.user.is_authenticated and request.user.is_superuser
