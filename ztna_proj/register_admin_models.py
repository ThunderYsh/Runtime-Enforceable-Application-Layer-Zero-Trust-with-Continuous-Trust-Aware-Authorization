from django.apps import apps
from .admin_site import admin_site

for model in apps.get_models():
    try:
        admin_site.register(model)
    except:
        pass
