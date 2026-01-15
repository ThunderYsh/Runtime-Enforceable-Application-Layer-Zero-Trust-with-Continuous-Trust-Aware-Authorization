# trustbroker/admin_panel.py
from django.contrib import admin
from django.utils.html import format_html

class ZTNAMixin:
    def changelist_view(self, request, extra_context=None):
        decision = getattr(request, "ztna_decision", None)

        if decision:
            extra_context = extra_context or {}
            extra_context["ztna"] = decision

        return super().changelist_view(request, extra_context=extra_context)
