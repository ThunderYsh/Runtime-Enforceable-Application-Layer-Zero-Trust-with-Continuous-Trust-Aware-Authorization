from django.contrib import admin
from .models import ApplicationResource

@admin.register(ApplicationResource)
class ApplicationResourceAdmin(admin.ModelAdmin):
    list_display = ('name', 'url', 'assigned_policy', 'criticality_level')
