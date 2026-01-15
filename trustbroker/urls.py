from django.urls import path
from . import views

urlpatterns = [
    path("analytics/", views.trust_analytics_view, name="trust_analytics"),
]
