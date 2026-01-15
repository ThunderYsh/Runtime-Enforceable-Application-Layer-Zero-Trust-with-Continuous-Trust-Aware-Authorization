# ztna/views.py
from datetime import timedelta
import io, base64, qrcode, subprocess, psutil
from io import BytesIO
import pyotp

from django.views.decorators.csrf import csrf_protect
from django.http import JsonResponse, HttpResponse, HttpResponseForbidden
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_date
from django.core.mail import send_mail
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

# MODELS
from idp.models import UserProfile
from appsrv.models import ApplicationResource
from .models import ZTNARequest, File

# SIEM (✅ always use helper)
from siem.utils import audit_log

# ZTNA logging
from ztna.utils import log_ztna

# TRUST
from trustbroker.utils import event_penalty
from trustbroker.models import TrustScore, TrustEvent

# POLICY
from policy.enforcer import enforce_access
from policy.models import DeviceFingerprintRecord
from ztna.device_score import calculate_device_score

from datetime import timedelta

def is_stepup_valid(request):
    """
    Step-up MFA is time-bounded (5 minutes).
    Used only for sensitive operations.
    """
    until = request.session.get("mfa_stepup_passed_until")
    if not until:
        return False
    return timezone.now().timestamp() < float(until)

# -----------------------------
# DOCKER HELPERS
# -----------------------------
DOCKER_DESKTOP = r"C:\Program Files\Docker\Docker\Docker Desktop.exe"

def is_docker_running():
    for p in psutil.process_iter(attrs=["name"]):
        if p.info["name"] and "Docker Desktop" in p.info["name"]:
            return True
    return False

def is_engine_running():
    try:
        out = subprocess.check_output(["docker", "info"], stderr=subprocess.STDOUT, text=True)
        return "Server Version" in out
    except:
        return False


# -----------------------------
# ZTNA SIMULATION
# -----------------------------
def simulate_ztna_request(request, user_id, app_id):
    try:
        user_profile = UserProfile.objects.get(id=user_id)
        app_resource = ApplicationResource.objects.get(id=app_id)
    except:
        return JsonResponse({"error": "Invalid user or application ID"}, status=404)

    ztna_req = ZTNARequest.objects.create(
        user_profile=user_profile,
        app_resource=app_resource,
        ip_address=request.META.get("REMOTE_ADDR", "127.0.0.1"),
        location="Unknown",
    )

    #  Run enforcement
    ztna_req.evaluate_request(
        device_score=50,
        mfa_passed=False,
    )

    return JsonResponse({
        "user": user_profile.user.username,
        "app": app_resource.name,
        "status": ztna_req.status,
        "reason": ztna_req.decision_reason,
        "policy_rule_id": getattr(ztna_req, "policy_rule_id", None),
    })


# -----------------------------
# DEVELOPER DASHBOARD
# -----------------------------
@login_required
def developer_dashboard(request):
    from siem.models import AuditLog
    logs = AuditLog.objects.select_related("user_profile").order_by("-timestamp")[:20]
    return render(request, "developer_dashboard.html", {"logs": logs})


# -----------------------------
# LOGIN / REGISTER / MFA
# -----------------------------
@csrf_protect
def login_view(request):
    list(messages.get_messages(request))

    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")

        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)

            profile, _ = UserProfile.objects.get_or_create(user=user)
            profile.ensure_totp()

            request.session["mfa_login_passed"] = False
            request.session["mfa_stepup_passed_until"] = None
            request.session.modified = True
            return redirect("mfa")

        # WRONG PASSWORD → penalty
        user_obj = User.objects.filter(username=username).first()
        if user_obj:
            profile = UserProfile.objects.filter(user=user_obj).first()
            if profile:
                event_penalty(profile, "bad_password", request.META.get("REMOTE_ADDR"))

        messages.error(request, "Invalid username or password")
        return redirect("login")

    return render(request, "login.html")


def register_view(request):
    if request.method == "POST":
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()

            profile, _ = UserProfile.objects.get_or_create(user=user)
            profile.ensure_totp()
            profile.is_device_registered = False
            profile.save()

            # FIXED logging
            audit_log(
                user_profile=profile,
                action="User registered",
                status="SUCCESS",
                ip=request.META.get("REMOTE_ADDR", ""),
            )

            login(request, user)
            request.session["mfa_passed"] = False
            request.session.modified = True
            return redirect("mfa")

        messages.error(request, "Fix highlighted errors.")
    else:
        form = UserCreationForm()

    return render(request, "register.html", {"form": form})


@login_required
def mfa_view(request):
    profile, _ = UserProfile.objects.get_or_create(user=request.user)

    secret = profile.ensure_totp()
    totp = pyotp.TOTP(secret)

    if request.method == "POST":
        token = request.POST.get("token", "").strip()

        if totp.verify(token):
            profile.is_device_registered = True
            profile.save()

            request.session["mfa_login_passed"] = True
            request.session.modified = True

            ts, _ = TrustScore.objects.get_or_create(user_profile=profile)
            ts.recovery_after_mfa()

            # update device fingerprint record
            fp = getattr(request, "device_fingerprint", {}) or {}
            fp_hash = fp.get("hash") or "unknown"
            fp_raw = fp.get("raw") or "{}"
            ip = request.META.get("REMOTE_ADDR", "")

            if fp_hash and fp_hash != "unknown":
                DeviceFingerprintRecord.objects.update_or_create(
                    user_profile=profile,
                    fingerprint=fp_hash,
                    defaults={
                        "raw": fp_raw,
                        "last_ip": ip,
                        "last_seen": timezone.now(),
                    },
                )

            audit_log(
                user_profile=profile,
                action="MFA verification success",
                status="SUCCESS",
                ip=request.META.get("REMOTE_ADDR", ""),
            )
            return redirect("dashboard")

        # MFA fail
        audit_log(
            user_profile=profile,
            action="MFA verification failed",
            status="FAILURE",
            ip=request.META.get("REMOTE_ADDR", ""),
        )
        event_penalty(profile, "mfa_fail", request.META.get("REMOTE_ADDR"))
        messages.error(request, "Invalid code")
        return redirect("mfa")

    qr_image = None
    if not profile.is_device_registered:
        uri = totp.provisioning_uri(name=request.user.username, issuer_name="ZTNA Portal")
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_image = base64.b64encode(buf.getvalue()).decode()

    return render(request, "mfa.html", {
        "qr_image": qr_image,
        "secret": secret if not profile.is_device_registered else None,
        "is_registered": profile.is_device_registered
    })


@login_required
def reset_mfa_request_view(request):
    if request.method == "POST":
        password = request.POST.get("password", "")
        user = authenticate(request, username=request.user.username, password=password)

        if not user:
            messages.error(request, "Incorrect password.")
            return redirect("reset_mfa_request")

        profile = UserProfile.objects.get(user=user)
        profile.totp_secret = pyotp.random_base32()
        profile.is_device_registered = False
        profile.save()

        audit_log(
            user_profile=profile,
            action="MFA reset",
            status="SUCCESS",
            ip=request.META.get("REMOTE_ADDR", ""),
        )

        return redirect("mfa")

    return render(request, "reset_mfa_confirm.html")

@login_required
def stepup_mfa_view(request):
    profile = UserProfile.objects.get(user=request.user)

    secret = profile.ensure_totp()
    totp = pyotp.TOTP(secret)

    if request.method == "POST":
        token = request.POST.get("token", "").strip()

        if totp.verify(token):
            # ✅ step-up MFA valid for 5 minutes
            request.session["mfa_stepup_passed_until"] = (
                timezone.now() + timedelta(minutes=5)
            ).timestamp()

            request.session.modified = True

            AuditLog.objects.create(
                user_profile=profile,
                action="Step-up MFA Success",
                status="SUCCESS",
                ip=request.META.get("REMOTE_ADDR", ""),
            )

            next_url = request.session.pop("stepup_next", "/ztna/dashboard/")
            return redirect(next_url)

        AuditLog.objects.create(
            user_profile=profile,
            action="Step-up MFA Failed",
            status="FAILURE",
            ip=request.META.get("REMOTE_ADDR", ""),
        )

        messages.error(request, "Invalid step-up MFA code")
        return render(request, "stepup_mfa.html", {"error": "Invalid OTP"})


    return render(request, "stepup_mfa.html")


# -----------------------------
# DASHBOARD
# -----------------------------
MIN_TRUST = 0.60

@login_required
def dashboard(request):
    user = request.user
    profile = UserProfile.objects.get(user=user)
    ip = request.META.get("REMOTE_ADDR", "")

    # 0) ZTNA attempt log (if your log_ztna supports status-only mode)
    log_ztna(
        user=user,
        app_name="Dashboard",
        ip=ip,
        status="ATTEMPT",
        reason="access dashboard",
    )

    # 1) MFA required
    if not request.session.get("mfa_login_passed", False):
        request.session["stepup_next"] = request.get_full_path()
        request.session.modified = True
        return redirect("stepup_mfa")

    # 2) device_score default 50
    device_score = getattr(request, "device_score", 50)

    # 3) policy engine decision
    decision = enforce_access(
        user=user,
        ip=ip,
        protected_link=None,
        device_score=device_score,
        mfa_passed=request.session.get("mfa_login_passed", False),
    )

    # ✅ FIX: app_resource was undefined in your code (CRASH)
    # Use Dashboard as resource name (or app model if you have one)
    log_ztna(
        user=user,
        app_name="Dashboard",
        ip=ip,
        decision=decision,
    )

    dashboard_trust = decision.get("dashboard_trust", 100)
    action = decision.get("action")

    # 4) hard block
    if action == "blocked":
        audit_log(
            user_profile=profile,
            action="Dashboard blocked by ZTNA policies",
            status="BLOCKED",
            ip=ip,
            policy_rule_id=decision.get("policy_rule_id"),
        )
        event_penalty(profile, "blocked", ip)
        return HttpResponseForbidden("Blocked by ZTNA policies")

    # 5) require MFA again
    if action == "mfa":
        audit_log(
            user_profile=profile,
            action="Dashboard requires MFA (step-up)",
            status="FAILURE",
            ip=ip,
            policy_rule_id=decision.get("policy_rule_id"),
        )
        request.session["mfa_next"] = request.get_full_path()
        request.session.modified = True
        return redirect("mfa")

    # 6) behavioral trust update (your model)
    ts, _ = TrustScore.objects.get_or_create(user_profile=profile)
    ts.hourly_recovery()
    ts.recovery_after_safe_action()

    behavioral_trust = round(ts.overall_trust, 3)
    status = "Allowed" if behavioral_trust >= MIN_TRUST else "Not Allowed"

    # 7) feature gate
    features = []
    if status == "Allowed":
        features = [
            {"name": "Create File", "url": "create_file"},
            {"name": "Edit File", "url": "edit_file"},
            {"name": "Share File", "url": "share_file"},
            {"name": "Fire Commands", "url": "fire_cmds"},
            {"name": "View Logs", "url": "view_logs"},
            {"name": "Reset MFA Device", "url": "reset_mfa_request"},
            {"name": "Trust Analytics", "url": "trust_analytics"},
        ]

    # 8) success/deny logs (non-admin)
    if not user.is_superuser:
        if status == "Allowed":
            audit_log(
                user_profile=profile,
                action="Dashboard access",
                status="SUCCESS",
                ip=ip,
                policy_rule_id=decision.get("policy_rule_id"),
            )
        else:
            audit_log(
                user_profile=profile,
                action="Dashboard access blocked by low behavioral trust",
                status="BLOCKED",
                ip=ip,
                policy_rule_id=decision.get("policy_rule_id"),
            )

    # 9) superuser override
    if user.is_superuser:
        return render(request, "dashboard.html", {
            "decision": {"allowed": True, "notes": ["admin_override"]},
            "status": "Allowed",
            "dashboard_trust": 100,
            "trust": 1.0,
            "min_trust": 0,
            "features": features,
        })

    # 10) final render
    return render(request, "dashboard.html", {
        "decision": decision,
        "status": status,
        "dashboard_trust": dashboard_trust,
        "trust": behavioral_trust,
        "min_trust": MIN_TRUST,
        "features": features,
    })





# FILE CRUD
@login_required
def create_file_view(request):
    profile = UserProfile.objects.get(user=request.user)
    ip = request.META.get("REMOTE_ADDR", "")

    log_ztna(
        user=request.user,
        app_name="File Service",
        ip=ip,
        status="APPROVED",
        reason="open create file page",
    )

    query = request.GET.get("q", "")
    files = File.objects.filter(user=request.user, name__icontains=query).order_by("-updated_at")

    edit_file = None
    if request.GET.get("edit"):
        edit_file = File.objects.filter(id=request.GET.get("edit"), user=request.user).first()

    if request.method == "POST":
        file_id = request.POST.get("file_id")
        filename = request.POST.get("filename", "").strip()
        content = request.POST.get("content", "")

        # ------------------------------
        # UPDATE EXISTING FILE
        # ------------------------------
        if file_id:
            file_obj = File.objects.get(id=file_id, user=request.user)
            file_obj.name = filename
            file_obj.content = content

            password_event = None

            # 1) REMOVE PASSWORD
            if request.POST.get("remove_password"):
                if file_obj.is_protected:
                    file_obj.is_protected = False
                    file_obj.password_hash = ""
                    password_event = "Password removed"

            # 2) CHANGE PASSWORD
            elif request.POST.get("change_password"):
                new_pwd = request.POST.get("new_file_password", "").strip()
                if new_pwd:
                    file_obj.set_password(new_pwd)
                    password_event = "Password changed"

            # 3) SET PASSWORD (previously unprotected)
            elif request.POST.get("protect"):
                pwd = request.POST.get("file_password", "").strip()
                if pwd:
                    file_obj.set_password(pwd)
                    password_event = "Password set"

            file_obj.save()

            audit_log(
                user_profile=profile,
                action=f"Updated file: {file_obj.name}" + (f" ({password_event})" if password_event else ""),
                status="SUCCESS",
                ip=ip,
            )

        # ------------------------------
        # CREATE NEW FILE
        # ------------------------------
        else:
            file_obj = File.objects.create(
                user=request.user,
                name=filename,
                content=content
            )

            password_event = None

            # Only initial protect makes sense on create
            if request.POST.get("protect"):
                pwd = request.POST.get("file_password", "").strip()
                if pwd:
                    file_obj.set_password(pwd)
                    file_obj.save()
                    password_event = "Password protected"

            audit_log(
                user_profile=profile,
                action=f"Created file: {file_obj.name}" + (f" ({password_event})" if password_event else ""),
                status="SUCCESS",
                ip=ip,
            )

        return redirect("create_file")

    return render(request, "create_file.html", {"files": files, "edit_file": edit_file})



@login_required
def edit_file_view(request):
    profile = UserProfile.objects.get(user=request.user)
    ip = request.META.get("REMOTE_ADDR", "")

    log_ztna(
        user=request.user,
        app_name="File Service",
        ip=ip,
        status="APPROVED",
        reason="open edit file page",
    )

    files = File.objects.filter(user=request.user)

    active_id = request.POST.get("file_id") or request.GET.get("file_id")
    active_content = ""

    if active_id:
        file_obj = File.objects.filter(id=active_id, user=request.user).first()
        if file_obj:
            active_content = file_obj.content

            if request.method == "POST":
                file_obj.content = request.POST.get("content")
                file_obj.save()

                audit_log(
                    user_profile=profile,
                    action=f"Edited file: {file_obj.name}",
                    status="SUCCESS",
                    ip=ip,
                )

    return render(request, "edit_file.html", {
        "files": files,
        "active_id": active_id,
        "active_content": active_content
    })


@login_required
def delete_file_view(request, file_id):
    profile = UserProfile.objects.get(user=request.user)
    ip = request.META.get("REMOTE_ADDR", "")

    log_ztna(
        user=request.user,
        app_name="File Service",
        ip=ip,
        status="APPROVED",
        reason="delete file",
    )

    f = get_object_or_404(File, id=file_id, user=request.user)
    name = f.name
    f.delete()

    audit_log(
        user_profile=profile,
        action=f"Deleted file: {name}",
        status="SUCCESS",
        ip=ip,
    )

    return redirect("create_file")


@login_required
def download_file_txt(request, file_id):
    profile = UserProfile.objects.get(user=request.user)
    ip = request.META.get("REMOTE_ADDR", "")

    f = get_object_or_404(File, id=file_id, user=request.user)

    response = HttpResponse(f.content, content_type="text/plain")
    response["Content-Disposition"] = f'attachment; filename="{f.name}.txt"'

    audit_log(
        user_profile=profile,
        action=f"Downloaded TXT: {f.name}",
        status="SUCCESS",
        ip=ip,
    )

    return response


@login_required
def download_file_pdf(request, file_id):
    profile = UserProfile.objects.get(user=request.user)
    ip = request.META.get("REMOTE_ADDR", "")

    f = get_object_or_404(File, id=file_id, user=request.user)

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)

    styles = getSampleStyleSheet()
    title = ParagraphStyle("Title", parent=styles["Heading1"], fontSize=16)
    body = ParagraphStyle("Body", parent=styles["Normal"], fontSize=11, leading=16)

    story = [Paragraph(f.name, title)]
    for line in f.content.split("\n"):
        story.append(Paragraph(line, body))
        story.append(Spacer(1, 10))

    doc.build(story)
    pdf = buffer.getvalue()
    buffer.close()

    resp = HttpResponse(pdf, content_type="application/pdf")
    resp["Content-Disposition"] = f'attachment; filename="{f.name}.pdf"'

    audit_log(
        user_profile=profile,
        action=f"Downloaded PDF: {f.name}",
        status="SUCCESS",
        ip=ip,
    )

    return resp


@login_required
def decrypt_file_view(request, file_id):
    pwd = request.GET.get("pwd", "")
    f = get_object_or_404(File, id=file_id, user=request.user)

    if not f.is_protected:
        return JsonResponse({"ok": False, "error": "Not protected"})

    if not f.check_password(pwd):
        return JsonResponse({"ok": False, "error": "wrong_password"})

    return JsonResponse({"ok": True, "content": f.content})


@login_required
def download_protected_txt(request, file_id):
    profile = UserProfile.objects.get(user=request.user)
    ip = request.META.get("REMOTE_ADDR", "")

    pwd = request.GET.get("pwd", "")
    f = get_object_or_404(File, id=file_id, user=request.user)

    # Validate password
    if f.is_protected and not f.check_password(pwd):
        return HttpResponse("Wrong password!", status=403)

    response = HttpResponse(f.content, content_type="text/plain")
    response["Content-Disposition"] = f'attachment; filename="{f.name}.txt"'

    audit_log(
        user_profile=profile,
        action=f"Downloaded PROTECTED TXT: {f.name}",
        status="SUCCESS",
        ip=ip,
    )

    return response


@login_required
def download_protected_pdf(request, file_id):
    profile = UserProfile.objects.get(user=request.user)
    ip = request.META.get("REMOTE_ADDR", "")

    pwd = request.GET.get("pwd", "")
    f = get_object_or_404(File, id=file_id, user=request.user)

    # Validate password
    if f.is_protected and not f.check_password(pwd):
        return HttpResponse("Wrong password!", status=403)

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)

    styles = getSampleStyleSheet()
    title = ParagraphStyle("Title", parent=styles["Heading1"], fontSize=16)
    body = ParagraphStyle("Body", parent=styles["Normal"], fontSize=11, leading=16)

    story = [Paragraph(f.name, title)]
    for line in f.content.split("\n"):
        story.append(Paragraph(line, body))
        story.append(Spacer(1, 10))

    doc.build(story)
    pdf = buffer.getvalue()
    buffer.close()

    response = HttpResponse(pdf, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="{f.name}.pdf"'

    audit_log(
        user_profile=profile,
        action=f"Downloaded PROTECTED PDF: {f.name}",
        status="SUCCESS",
        ip=ip,
    )

    return response


@login_required
def share_file_view(request):
    profile = UserProfile.objects.get(user=request.user)
    ip = request.META.get("REMOTE_ADDR", "")

    log_ztna(
        user=request.user,
        app_name="File Service",
        ip=ip,
        status="APPROVED",
        reason="open share file page",
    )

    files = File.objects.filter(user=request.user)

    if request.method == "POST":
        file_id = request.POST.get("file_id")
        recipients_raw = request.POST.get("share_with", "")
        mode = request.POST.get("mode")

        if not file_id or not recipients_raw:
            messages.error(request, "Select a file and enter recipients.")
            return redirect("share_file")

        f = File.objects.filter(id=file_id, user=request.user).first()
        if not f:
            messages.error(request, "Invalid file.")
            return redirect("share_file")

        recipients = [r.strip() for r in recipients_raw.split(",") if r.strip()]

        # ---- APPLY ACCESS MODE ----
        f.share_mode = mode
        f.allowed_users = ",".join(recipients)

        if mode == "expire":
            f.expire_at = timezone.now() + timedelta(hours=24)
        else:
            f.expire_at = None

        f.save()

        # BUILD SHARE URL
        share_url = request.build_absolute_uri(
            reverse("shared_file_view", args=[f.id])
        )

        # BUILD EMAIL BODY
        email_body = f"""
{request.user.username} has shared a file with you.

File: {f.name}
Access Mode: {f.share_mode.upper()}

Open the file using this link:
{share_url}
"""

        # ---- PASSWORD PROTECTION NOTICE ----
        if f.is_protected:
            email_body += """

⚠️ PASSWORD REQUIRED

This file is password protected.
You must ask the sender for the password.

(For security reasons, the password is NOT sent through email.)
"""

        send_mail(
            subject=f"File Shared With You: {f.name}",
            message=email_body,
            from_email="bholeyash2002@gmail.com",
            recipient_list=recipients,
            fail_silently=False,
        )

        audit_log(
            user_profile=profile,
            action=f"Shared file {f.name} ({mode})",
            status="SUCCESS",
            ip=ip,
        )

        messages.success(request, f"Shared in '{mode}' mode. Email sent.")
        return redirect("share_file")

    return render(request, "share_file.html", {"files": files})


def shared_file_view(request, file_id):
    f = get_object_or_404(File, id=file_id)
    ip = request.META.get("REMOTE_ADDR", "unknown")
    remaining_seconds = None

    # 1) EXPIRE MODE
    if f.share_mode == "expire":
        if not request.user.is_authenticated:
            return render(request, "access_denied.html", {"reason": "Login required."})

        if f.expire_at and timezone.now() >= f.expire_at:
            p = UserProfile.objects.filter(user=request.user).first()
            if p:
                event_penalty(p, "link_fail", ip)
            return render(request, "access_denied.html", {"reason": "Link expired."})

        remaining_seconds = int((f.expire_at - timezone.now()).total_seconds())

    # 2) STRICT MODE
    if f.share_mode == "strict":
        if not request.user.is_authenticated:
            return render(request, "access_denied.html", {"reason": "Login required."})

        allowed = [u.strip().lower() for u in (f.allowed_users or "").split(",")]
        if request.user.username.lower() not in allowed:
            p = UserProfile.objects.filter(user=request.user).first()
            if p:
                event_penalty(p, "link_fail", ip)
            return render(request, "access_denied.html", {"reason": "Not authorized."})

    # 3) PASSWORD PROTECTION
    if f.is_protected:
        pwd = request.GET.get("pwd", "").strip()

        if not pwd:
            return render(request, "shared_password_prompt.html", {"file": f})

        if not f.check_password(pwd):
            return render(
                request,
                "shared_password_prompt.html",
                {"file": f, "error": "Wrong password!"}
            )

    return render(request, "shared_file_view.html", {
        "file": f,
        "remaining_seconds": remaining_seconds,
        "access_status": f.share_mode.capitalize(),
        "expire_at": f.expire_at
    })


# LOGS
@login_required
def view_logs_page(request):
    ip = request.META.get("REMOTE_ADDR", "")

    log_ztna(
        user=request.user,
        app_name="Logs",
        ip=ip,
        status="APPROVED",
        reason="view logs",
    )

    # ✅ OPTIONAL BUT RECOMMENDED: ZTNA enforcement before allowing logs
    decision = enforce_access(
        user=request.user,
        ip=ip,
        protected_link=None,
        device_score=getattr(request, "device_score", 50),
        mfa_passed=request.session.get("mfa_passed", False),
    )

    if decision.get("action") != "allow":
        audit_log(
            user=request.user,
            action="Denied access to audit logs (ZTNA enforcement)",
            status="BLOCKED",
            ip=ip,
            policy_rule_id=decision.get("policy_rule_id"),
        )
        return HttpResponseForbidden("Denied by ZTNA enforcement")

    # ✅ Import model ONLY where needed for querying (safe + avoids global spam)
    from siem.models import AuditLog

    if request.user.is_superuser:
        logs = AuditLog.objects.all().order_by("-timestamp")
    else:
        logs = AuditLog.objects.filter(user_profile__user=request.user).order_by("-timestamp")

    search = request.GET.get("search")
    if search:
        logs = logs.filter(action__icontains=search)

    user_filter = request.GET.get("user")
    if request.user.is_superuser and user_filter:
        logs = logs.filter(user_profile__user__id=user_filter)

    action_filter = request.GET.get("action")
    if action_filter and action_filter != "all":
        logs = logs.filter(action__icontains=action_filter)

    start = request.GET.get("start_date")
    end = request.GET.get("end_date")
    if start:
        logs = logs.filter(timestamp__date__gte=parse_date(start))
    if end:
        logs = logs.filter(timestamp__date__lte=parse_date(end))

    # Export CSV
    if request.GET.get("export") == "csv":
        import csv
        response = HttpResponse(content_type="text/csv")
        response["Content-Disposition"] = "attachment; filename=audit_logs.csv"
        writer = csv.writer(response)
        writer.writerow(["User", "Action", "Status", "Timestamp", "PolicyRuleID"])
        for l in logs:
            writer.writerow([
                l.user_profile.user.username,
                l.action,
                l.status,
                l.timestamp,
                getattr(l, "policy_rule_id", None),
            ])
        return response

   
    audit_log(
        user=request.user,
        action="Viewed audit logs",
        status="SUCCESS",
        ip=ip,
        policy_rule_id=decision.get("policy_rule_id"),
    )

    return render(request, "view_logs.html", {
        "logs": logs,
        "all_users": User.objects.all() if request.user.is_superuser else None
    })



# ----------------------------------------------------
# TRUST ANALYTICS – USER
# ----------------------------------------------------
@login_required
def trust_analytics_view(request):
    profile = UserProfile.objects.get(user=request.user)
    ip = request.META.get("REMOTE_ADDR", "")

    log_ztna(
        user=request.user,
        app_name="Trust Analytics",
        ip=ip,
        status="APPROVED",
        reason="access trust analytics",
    )

    
    decision = enforce_access(
        user=request.user,
        ip=ip,
        protected_link=None,
        device_score=getattr(request, "device_score", 50),
        mfa_passed=request.session.get("mfa_passed", False),
    )
    if decision.get("action") != "allow":
        audit_log(
            user_profile=profile,
            action="Denied access to trust analytics (ZTNA enforcement)",
            status="BLOCKED",
            ip=ip,
            policy_rule_id=decision.get("policy_rule_id"),
        )
        return HttpResponseForbidden("Denied by ZTNA enforcement")

    trust_score, _ = TrustScore.objects.get_or_create(user_profile=profile)
    trust_score.daily_recovery()

    events = TrustEvent.objects.filter(user_profile=profile).order_by("-timestamp")[:50]

    labels = [e.timestamp.strftime("%H:%M") for e in events[::-1]]
    values = [e.new_score for e in events[::-1]]

    event_count = {}
    for e in events:
        event_count[e.event_type] = event_count.get(e.event_type, 0) + 1

    audit_log(
        user_profile=profile,
        action="Viewed trust analytics",
        status="SUCCESS",
        ip=ip,
        policy_rule_id=decision.get("policy_rule_id"),
    )

    return render(request, "trust_analytics.html", {
        "trust_score": trust_score,
        "events": events,
        "timeline_labels": labels,
        "timeline_scores": values,
        "event_count": event_count
    })



# ----------------------------------------------------
# TRUST ANALYTICS – ADMIN
# ----------------------------------------------------
from django.contrib.admin.views.decorators import staff_member_required

@staff_member_required
def trust_admin_analytics_view(request):
    profiles = UserProfile.objects.select_related("user").all()
    data = []

    for p in profiles:
        ts, _ = TrustScore.objects.get_or_create(user_profile=p)
        ts.daily_recovery()
        data.append({
            "username": p.user.username,
            "trust": ts.overall_trust,
            "id": p.id
        })

    data_sorted = sorted(data, key=lambda x: x["trust"], reverse=True)
    labels = [d["username"] for d in data_sorted]
    values = [d["trust"] for d in data_sorted]
    ids = [d["id"] for d in data_sorted]

    events = TrustEvent.objects.select_related("user_profile").order_by("-timestamp")[:40]

    event_count = {}
    for e in events:
        event_count[e.event_type] = event_count.get(e.event_type, 0) + 1

    return render(request, "trust_admin_analytics.html", {
        "users": data_sorted,
        "labels": labels,
        "trust_values": values,
        "user_ids": ids,
        "event_count": event_count,
        "events": events
    })


@staff_member_required
def trust_admin_user_detail(request, profile_id):
    profile = get_object_or_404(UserProfile, id=profile_id)
    trust_score, _ = TrustScore.objects.get_or_create(user_profile=profile)
    trust_score.daily_recovery()

    events = TrustEvent.objects.filter(user_profile=profile).order_by("-timestamp")[:50]
    labels = [e.timestamp.strftime("%H:%M") for e in reversed(events)]
    values = [e.new_score for e in reversed(events)]

    return render(request, "trust_admin_user_detail.html", {
        "profile": profile,
        "trust_score": trust_score,
        "timeline_labels": labels,
        "timeline_scores": values,
        "events": events
    })


# FIRE COMMANDS
@login_required
def fire_cmds_view(request):
    profile = UserProfile.objects.get(user=request.user)
    ip = request.META.get("REMOTE_ADDR", "unknown")

    log_ztna(
        user=request.user,
        app_name="Fire Commands",
        ip=ip,
        status="APPROVED",
        reason="fire commands",
    )

    result = None

    # --- Admin Override ---
    if not request.user.is_superuser:
        ts, _ = TrustScore.objects.get_or_create(user_profile=profile)
        if ts.overall_trust < 0.60:
            audit_log(
                user_profile=profile,
                action="Denied command execution (trust too low)",
                status="BLOCKED",
                ip=ip,
            )
            return HttpResponseForbidden("Trust too low to run system commands.")

    if request.method == "POST":
        cmd = request.POST.get("command")

        if cmd == "start_docker":
            try:
                subprocess.Popen(DOCKER_DESKTOP)
                result = "Docker starting..."
                audit_log(user_profile=profile, action="Started Docker", status="SUCCESS", ip=ip)
            except:
                result = "Error starting Docker"
                audit_log(user_profile=profile, action="Failed to start Docker", status="FAILURE", ip=ip)

        elif cmd == "stop_docker":
            try:
                subprocess.run(["taskkill", "/F", "/IM", "Docker Desktop.exe"])
                subprocess.run(["taskkill", "/F", "/IM", "com.docker.backend.exe"])
                result = "Docker stopped."
                audit_log(user_profile=profile, action="Stopped Docker", status="SUCCESS", ip=ip)
            except:
                result = "Error stopping Docker"
                audit_log(user_profile=profile, action="Failed to stop Docker", status="FAILURE", ip=ip)

        elif cmd == "restart_docker":
            try:
                subprocess.run(["taskkill", "/F", "/IM", "Docker Desktop.exe"])
                subprocess.run(["taskkill", "/F", "/IM", "com.docker.backend.exe"])
                subprocess.Popen(DOCKER_DESKTOP)
                result = "Docker restarting..."
                audit_log(user_profile=profile, action="Restarted Docker", status="SUCCESS", ip=ip)
            except:
                result = "Error restarting Docker"
                audit_log(user_profile=profile, action="Failed to restart Docker", status="FAILURE", ip=ip)

        elif cmd == "check_status":
            ui = is_docker_running()
            engine = is_engine_running()

            if ui and engine:
                result = "Docker is running"
            elif ui and not engine:
                result = "Docker UI open but engine not running"
            else:
                result = "Docker is not running"

            audit_log(user_profile=profile, action="Checked Docker status", status="SUCCESS", ip=ip)

    return render(request, "fire_cmds.html", {"result": result})


from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from idp.models import UserProfile
from policy.models import DeviceFingerprintRecord
from ztna.device_score import calculate_device_score

@login_required
def device_trust_report(request):
    profile = UserProfile.objects.get(user=request.user)
    ip = request.META.get("REMOTE_ADDR", "")

    audit_log(
        user_profile=profile,
        action="Viewed device trust report",
        status="SUCCESS",
        ip=ip,
    )

    fp = getattr(request, "device_fingerprint", None)

    # ✅ set device_score safely
    if fp and fp.get("hash"):
        request.device_score = calculate_device_score(fp["hash"])
    else:
        request.device_score = 20

    # ✅ If no fingerprint, show default report
    if not fp or not fp.get("hash"):
        return render(request, "device_trust_report.html", {
            "fp_hash": None,
            "score": 20,
            "risk": "Unknown / Unverified Device",
            "risk_color": "text-gray-400",
            "history": [],
        })

    fp_hash = fp["hash"]

    record, created = DeviceFingerprintRecord.objects.get_or_create(
        user_profile=profile,
        fingerprint=fp_hash,
        defaults={"last_ip": ip}
    )

    if not created:
        record.last_ip = ip
        record.save(update_fields=["last_ip"])

    score = calculate_device_score(fp_hash, debug_mode=False)
    calculate_device_score(fp_hash, debug_mode=True)

    if score >= 80:
        risk = "Low (Safe)"
        color = "text-green-400"
    elif score >= 60:
        risk = "Medium"
        color = "text-yellow-400"
    else:
        risk = "High"
        color = "text-red-400"

    history = DeviceFingerprintRecord.objects.filter(
        user_profile=profile
    ).order_by("-last_seen")

    return render(request, "device_trust_report.html", {
        "fp_hash": fp_hash,
        "score": score,
        "risk": risk,
        "risk_color": color,
        "history": history,
    })
