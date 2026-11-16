"""Minimal same-origin CSRF guard for the three state-changing POSTs.

A double-submit token is issued per session and required on every POST. This is
not an authentication system; it only stops a third-party page from silently
driving a revoke or upload in a logged-in operator's browser.
"""

from __future__ import annotations

import hmac
import secrets

from flask import request, session

TOKEN_KEY = "_csrf_token"
FORM_FIELD = "csrf_token"


def token() -> str:
    value = session.get(TOKEN_KEY)
    if not value:
        value = secrets.token_urlsafe(32)
        session[TOKEN_KEY] = value
    return value


def valid() -> bool:
    expected = session.get(TOKEN_KEY)
    supplied = request.form.get(FORM_FIELD, "")
    return bool(expected and supplied and hmac.compare_digest(expected, supplied))
