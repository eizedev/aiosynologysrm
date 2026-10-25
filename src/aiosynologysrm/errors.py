"""Exceptions raised by the client.

Messages never contain credentials, session ids or response bodies, so they are safe to log.
"""

from __future__ import annotations


class SrmError(Exception):
    """Base class for every error raised by this library."""


class SrmConnectionError(SrmError):
    """The router could not be reached or did not answer with valid HTTP."""


class SrmTimeoutError(SrmConnectionError):
    """The router did not answer within the configured timeout."""


class SrmCertificateError(SrmError):
    """The router's TLS certificate failed verification or does not match the pinned fingerprint.

    Not a connection error on purpose: retrying does not help. After a certificate renewal, fetch
    the new fingerprint with :func:`aiosynologysrm.get_certificate_fingerprint` and let the user
    confirm it before trusting it (in Home Assistant: a reauth or repair flow).
    """


class SrmResponseError(SrmError):
    """The router answered, but not with the expected structure."""


class SrmApiError(SrmError):
    """The router reported an error code for a request."""

    def __init__(self, code: int, api: str | None = None) -> None:
        """Store the numeric error code and, if known, the API name."""
        self.code = code
        self.api = api
        where = f" ({api})" if api else ""
        super().__init__(f"SRM API error {code}{where}")

    def __reduce__(self) -> tuple[type[SrmApiError], tuple[int, str | None]]:
        """Rebuild from code and API, so the error survives pickle and copy."""
        return (type(self), (self.code, self.api))


class SrmAuthenticationError(SrmApiError):
    """Login failed for a reason only the user can fix.

    Wrong account or password (400), disabled account (401), no permission (402), password expired
    or to be changed (408-410).

    Other login codes are plain :class:`SrmApiError`s and not remembered: they can be temporary,
    for example while the router restarts.
    """


class SrmTwoFactorRequiredError(SrmAuthenticationError):
    """The account has two-factor authentication enabled and a (new) code is needed.

    A code is sent with one login only. When the session ends later, the next login needs a fresh
    code, so unattended use needs an account without two-factor authentication.
    """


class SrmBlockedError(SrmApiError):
    """The router blocks logins from this IP address (code 407), usually after failed attempts.

    Not an authentication error: the credentials may be right (in Home Assistant a repair issue,
    not a reauth). Retrying does not help until the block expires or is lifted in SRM's auto block
    settings, so the client remembers it like a failed login; call ``login()`` once it has expired.
    """


class SrmSessionError(SrmApiError):
    """The router ended the session again right after a new login; the credentials are fine.

    Usually temporary (the router restarted, or another client ended the session); retry later.
    """


class SrmPermissionError(SrmApiError):
    """The account is logged in but may not use this API (SRM needs an admin account)."""


class SrmUnsupportedError(SrmApiError):
    """The router, its firmware or the API version does not offer the requested call."""


class SrmNotAllowedError(SrmError):
    """The call is not on the library's read-only allowlist and was not sent."""
