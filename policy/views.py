import json
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required, user_passes_test
from django.views.decorators.http import require_POST

from .models import Policy, PolicyRule


# -------------------------------
# Helper — only admin/staff access
# -------------------------------
def is_admin(user):
    return user.is_staff or user.is_superuser


# -------------------------------
# POLICY LIST PAGE
# -------------------------------
@login_required
@user_passes_test(is_admin)
def policy_list(request):
    policies = Policy.objects.all().order_by("-last_modified")
    return render(request, "policy_list.html", {"policies": policies})


# -------------------------------
# POLICY DETAIL PAGE
# -------------------------------
@login_required
@user_passes_test(is_admin)
def policy_detail(request, pk):
    policy = get_object_or_404(Policy, pk=pk)
    return render(request, "policy_detail.html", {"policy": policy})


# -------------------------------
# CREATE POLICY (AJAX)
# -------------------------------
@login_required
@user_passes_test(is_admin)
def api_policy_create(request):
    if request.method != "POST":
        return JsonResponse({"error": "Invalid method"}, status=405)

    data = json.loads(request.body.decode())

    p = Policy.objects.create(
        name=data.get("name"),
        description=data.get("description", ""),
        sensitivity=data.get("sensitivity", 1),
        created_by=request.user
    )

    return JsonResponse({"status": "ok", "id": p.id})


# -------------------------------
# DELETE POLICY
# -------------------------------
@login_required
@user_passes_test(is_admin)
@require_POST
def api_policy_delete(request, policy_id):
    Policy.objects.filter(id=policy_id).delete()
    return JsonResponse({"status": "deleted"})


# -------------------------------
# CREATE RULE
# -------------------------------
@login_required
@user_passes_test(is_admin)
@require_POST
def api_rule_create(request, policy_id):
    policy = get_object_or_404(Policy, id=policy_id)
    data = json.loads(request.body.decode())

    rule = PolicyRule.objects.create(
        policy=policy,
        name=data["name"],
        condition=data["condition"],
        action=data["action"],
        priority=data["priority"]
    )

    return JsonResponse({"status": "ok", "id": rule.id})


# -------------------------------
# GET RULE (edit modal)
# -------------------------------
@login_required
@user_passes_test(is_admin)
def api_rule_get(request, rule_id):
    rule = get_object_or_404(PolicyRule, id=rule_id)

    return JsonResponse({
        "name": rule.name,
        "condition": rule.condition,
        "action": rule.action,
        "priority": rule.priority
    })


# -------------------------------
# EDIT RULE
# -------------------------------
@login_required
@user_passes_test(is_admin)
@require_POST
def api_rule_edit(request, rule_id):
    rule = get_object_or_404(PolicyRule, id=rule_id)
    data = json.loads(request.body.decode())

    rule.name = data["name"]
    rule.condition = data["condition"]
    rule.action = data["action"]
    rule.priority = data["priority"]
    rule.save()

    return JsonResponse({"status": "ok"})


# -------------------------------
# DELETE RULE
# -------------------------------
@login_required
@user_passes_test(is_admin)
@require_POST
def api_rule_delete(request, rule_id):
    PolicyRule.objects.filter(id=rule_id).delete()
    return JsonResponse({"status": "deleted"})

from django.shortcuts import redirect, get_object_or_404
from django.contrib.admin.views.decorators import staff_member_required

from .models import UserTemporaryBlock
from idp.models import UserProfile
from siem.utils import audit_log


@staff_member_required
def admin_unblock(request, block_id):
    block = get_object_or_404(UserTemporaryBlock, id=block_id)
    who = block.user.username if block.user else block.ip
    block.delete()

    profile = UserProfile.objects.filter(user=request.user).first()

    audit_log(
        user_profile=profile,
        action=f"Admin unblocked {who}",
        status="ADMIN_UNBLOCK",
        ip=request.META.get("REMOTE_ADDR"),
    )

    return redirect("/admin/policy/usertemporaryblock/")


