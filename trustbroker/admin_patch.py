
from django.contrib.admin.sites import AdminSite
from django.contrib.auth import authenticate
from trustbroker.utils import event_penalty
from idp.models import UserProfile

class ZTNAAdminSite(AdminSite):

    def login(self, request, extra_context=None):

        if request.method == "POST":
            username = request.POST.get("username")
            password = request.POST.get("password")

            user = authenticate(request, username=username, password=password)

            if user is None:
                # Failed login → penalize trust
                from django.contrib.auth.models import User
                user_obj = User.objects.filter(username=username).first()
                if user_obj and not user_obj.is_superuser:
                  profile = UserProfile.objects.get(user=user_obj)
                  event_penalty(profile, "bad_password", request.META.get("REMOTE_ADDR"))

        return super().login(request, extra_context)
