from django.contrib import admin
from .models import AuditLog

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):  
    list_display = ('user_profile', 'action', 'status', 'timestamp')
