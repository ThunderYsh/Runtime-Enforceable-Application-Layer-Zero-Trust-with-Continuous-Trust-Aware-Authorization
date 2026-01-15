import threading
from django.core.mail import send_mail
from django.conf import settings

def send_async_email(subject, message, to_list):
    """Runs email sending in background thread — Windows friendly."""
    t = threading.Thread(target=_send, args=(subject, message, to_list))
    t.daemon = True
    t.start()

def _send(subject, message, to_list):
    try:
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, to_list)
    except Exception as e:
        print("Email send failed:", e)
