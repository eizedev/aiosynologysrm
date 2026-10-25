# Errors

Every error from talking to the router derives from `SrmError`; wrong arguments raise
`ValueError` (an invalid host) or `TypeError` (`supports()` with something that is not a getter).

| Error | Meaning | In Home Assistant |
| --- | --- | --- |
| `SrmAuthenticationError` | wrong user or password, disabled account, no permission, expired password (400-402, 408-410) | `ConfigEntryAuthFailed` (reauth) |
| `SrmTwoFactorRequiredError` | the account uses two-factor authentication; pass a fresh `otp_code` | `ConfigEntryAuthFailed`; use an account without 2FA |
| `SrmBlockedError` | the router blocks logins from this address after failed attempts; credentials may be fine | repair issue; call `login()` only after the user unblocked the address or the block expired (`get_auto_block().expire_day` days, `0` = never); every attempt counts towards the block |
| `SrmCertificateError` | the certificate is not trusted or does not match the pinned fingerprint | reauth or repair: confirm the new fingerprint |
| `SrmConnectionError` / `SrmTimeoutError` | the router could not be reached | `ConfigEntryNotReady` / `UpdateFailed` |
| `SrmSessionError` | the router ended the session right after a new login | `UpdateFailed` |
| `SrmUnsupportedError` | this router or firmware does not offer the requested data | skip the entity (`supports()`) |
| `SrmPermissionError` | the account may not use this API; SRM needs an administrator | repair issue |
| `SrmResponseError` | the router answered with something that is not a valid Web API answer | `UpdateFailed` |
| `SrmApiError` | any other code, including unknown login codes during a restart | `UpdateFailed` |

After a failed login (authentication, 2FA, blocked) the client sends no further logins until
`login()` is called, so polling cannot run into SRM's auto block. Each request has its own
`timeout`; one read can chain catalog, login and a retry, so wrap a whole update in
`asyncio.timeout()` if it must finish in a fixed time.

Error messages never contain passwords or session data, so they are safe to log. A traceback also shows the chained aiohttp error, which names the router's host and port: replace that before you post a traceback in public.
