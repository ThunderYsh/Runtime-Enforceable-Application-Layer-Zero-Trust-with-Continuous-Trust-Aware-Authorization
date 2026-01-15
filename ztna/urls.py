from django.urls import path
from . import views
from .views import simulate_ztna_request
from .views import decrypt_file_view


urlpatterns = [

    # ---- Simulation ----
    path('simulate/<int:user_id>/<int:app_id>/', simulate_ztna_request, name='simulate_ztna_request'),

    # ---- Authentication ----
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('mfa/', views.mfa_view, name='mfa'),
    path('reset-mfa/', views.reset_mfa_request_view, name='reset_mfa_request'),
    path("stepup-mfa/", views.stepup_mfa_view, name="stepup_mfa"),


    # ---- Dashboard ----
    path('dashboard/', views.dashboard, name='dashboard'),
    path('developer/', views.developer_dashboard, name='developer_dashboard'),

    # ---- Files ----
    path('create-file/', views.create_file_view, name='create_file'),
    path("decrypt-file/<int:file_id>/", decrypt_file_view, name="decrypt_file"),
    path('edit-file/', views.edit_file_view, name='edit_file'),
    path('delete-file/<int:file_id>/', views.delete_file_view, name='delete_file'),
    path('share-file/', views.share_file_view, name='share_file'),
    
    # Shared file viewer
    path('shared/view/<int:file_id>/', views.shared_file_view, name='shared_file_view'),

    # Downloads
    path('file/download/txt/<int:file_id>/', views.download_file_txt, name='download_file_txt'),
    path('file/download/pdf/<int:file_id>/', views.download_file_pdf, name='download_file_pdf'),
    path("download-protected/<int:file_id>/txt/", views.download_protected_txt, name="download_protected_txt"),
    path("download-protected/<int:file_id>/pdf/", views.download_protected_pdf, name="download_protected_pdf"),

    # ---- Command Firing ----
    path('fire-cmds/', views.fire_cmds_view, name='fire_cmds'),

    # ---- Logs ----
    path('logs/', views.view_logs_page, name='view_logs'),

    # ---- Trust Analytics ----
    path('trust/analytics/', views.trust_analytics_view, name='trust_analytics'),
    path('trust/admin/', views.trust_admin_analytics_view, name='trust_admin_analytics'),
    path('trust/admin/user/<int:profile_id>/', views.trust_admin_user_detail, name='trust_admin_user_detail'),
    path("device-trust/", views.device_trust_report, name="device_trust_report"),
]
