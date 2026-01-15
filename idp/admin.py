from django.contrib import admin
from .models import UserProfile

from django.contrib.auth.models import User
from trustbroker.admin_panel import ZTNAMixin

class UserAdmin(ZTNAMixin, admin.ModelAdmin):
    list_display = ("username", "email", "is_staff")

admin.site.unregister(User)
admin.site.register(User, UserAdmin)

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'is_device_registered', 'totp_secret')
