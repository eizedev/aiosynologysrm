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


class SrmAuthenticationError(SrmApiError):
    """Login failed: wrong credentials, disabled account or no permission."""


class SrmTwoFactorRequiredError(SrmAuthenticationError):
    """The account has two-factor authentication enabled and a code is needed."""


class SrmPermissionError(SrmApiError):
    """The account is logged in but may not use this API (SRM needs an admin account)."""


class SrmUnsupportedError(SrmApiError):
    """The router, its firmware or the API version does not offer the requested call."""


class SrmNotAllowedError(SrmError):
    """The call is not on the library's read-only allowlist and was not sent."""
