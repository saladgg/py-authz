from __future__ import annotations
from typing import Optional
from django.contrib.auth import get_user_model


User = get_user_model()


def get_or_create_user(subject: str, email: Optional[str] = None, username: Optional[str] = None):
    """Default user provisioning strategy.

    Library users can override this by providing their own backend or signal.
    """
    username = username or email or subject
    user, _ = User.objects.get_or_create(username=username, defaults={"email": email or ""})
    return user