from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required

from idp.models import UserProfile
from .models import TrustScore, TrustEvent


# ----------------------------------------------------
# TRUST ANALYTICS – USER
# ----------------------------------------------------
@login_required
def trust_analytics_view(request):
    # ✅ Correct profile lookup
    profile = get_object_or_404(UserProfile, user=request.user)

    ts, _ = TrustScore.objects.get_or_create(user_profile=profile)

    # Optional recovery bump
    if hasattr(ts, "daily_recovery"):
        ts.daily_recovery()

    current_trust = getattr(ts, "overall_trust", 1.0)

    # 50 most recent events for this user
    events = (
        TrustEvent.objects
        .filter(user_profile=profile)
        .order_by("-timestamp")[:50]
    )

    # Timeline oldest → newest
    ordered = list(events)[::-1]
    timeline_labels = [e.timestamp.strftime("%H:%M:%S") for e in ordered]
    timeline_scores = [round(float(e.new_score), 3) for e in ordered]

    # Event type distribution
    event_count = {}
    for e in events:
        event_count[e.event_type] = event_count.get(e.event_type, 0) + 1

    return render(request, "trust_analytics.html", {
        "trust_score": ts,
        "current_trust": round(float(current_trust), 3),
        "events": events,
        "timeline_labels": timeline_labels,
        "timeline_scores": timeline_scores,
        "event_labels": list(event_count.keys()),
        "event_values": list(event_count.values()),
    })


# ----------------------------------------------------
# TRUST ANALYTICS – ADMIN (OVERVIEW)
# ----------------------------------------------------
@staff_member_required
def trust_admin_analytics_view(request):
    profiles = UserProfile.objects.select_related("user").all()

    data = []
    for p in profiles:
        ts, _ = TrustScore.objects.get_or_create(user_profile=p)

        # Optional bump (same as user page)
        if hasattr(ts, "daily_recovery"):
            ts.daily_recovery()

        data.append({
            "username": p.user.username,
            "trust": float(getattr(ts, "overall_trust", 1.0)),
            "id": p.id,
        })

    # Sort by trust score descending
    data_sorted = sorted(data, key=lambda x: x["trust"], reverse=True)

    labels = [i["username"] for i in data_sorted]
    trust_values = [round(i["trust"], 3) for i in data_sorted]
    user_ids = [i["id"] for i in data_sorted]

    # Global recent trust events
    events = TrustEvent.objects.select_related("user_profile").order_by("-timestamp")[:40]

    event_count = {}
    for e in events:
        event_count[e.event_type] = event_count.get(e.event_type, 0) + 1

    return render(request, "trust_admin_analytics.html", {
        "users": data_sorted,
        "labels": labels,
        "trust_values": trust_values,
        "user_ids": user_ids,
        "event_count": event_count,
        "events": events,
    })


# ----------------------------------------------------
# TRUST ANALYTICS – ADMIN (USER DETAIL)
# ----------------------------------------------------
@staff_member_required
def trust_admin_user_detail(request, profile_id):
    profile = get_object_or_404(UserProfile, id=profile_id)

    trust, _ = TrustScore.objects.get_or_create(user_profile=profile)

    # Optional bump
    if hasattr(trust, "daily_recovery"):
        trust.daily_recovery()

    events = TrustEvent.objects.filter(user_profile=profile).order_by("-timestamp")[:50]

    timeline_labels = [e.timestamp.strftime("%H:%M:%S") for e in events[::-1]]
    timeline_scores = [round(float(e.new_score), 3) for e in events[::-1]]

    return render(request, "trust_admin_user_detail.html", {
        "profile": profile,
        "trust_score": trust,
        "timeline_labels": timeline_labels,
        "timeline_scores": timeline_scores,
        "events": events,
    })
