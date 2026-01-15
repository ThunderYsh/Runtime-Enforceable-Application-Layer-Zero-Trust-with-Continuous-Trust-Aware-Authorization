from django.urls import path
from . import views

urlpatterns = [
    path("", views.policy_list, name="policy_list"),
    path("p/<int:pk>/", views.policy_detail, name="policy_detail"),

    path("api/policy/create/", views.api_policy_create, name="api_policy_create"),
    path("api/policy/<int:policy_id>/delete/", views.api_policy_delete, name="api_policy_delete"),

    path("api/policy/<int:policy_id>/rule/create/", views.api_rule_create, name="api_rule_create"),
    path("api/rule/<int:rule_id>/get/", views.api_rule_get, name="api_rule_get"),
    path("api/rule/<int:rule_id>/edit/", views.api_rule_edit, name="api_rule_edit"),
    path("api/rule/<int:rule_id>/delete/", views.api_rule_delete, name="api_rule_delete"),
    path("admin/unblock/<int:block_id>/", views.admin_unblock, name="admin_unblock"),

]
