from .custom_admin import ZTNAAdminSite

# SINGLE instance used everywhere
admin_site = ZTNAAdminSite(name="ztna_admin")
