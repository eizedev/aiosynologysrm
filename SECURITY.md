# Security Policy

## Scope

This library only reads from Synology SRM routers. In scope: anything in this repository that
could leak credentials or session data, send a request that changes router settings, or let a
malicious router answer harm the program using the library.

Vulnerabilities in SRM itself belong to [Synology](https://www.synology.com/security).

## Reporting a vulnerability

Please report privately via GitHub's
[Report a vulnerability](https://github.com/eizedev/aiosynologysrm/security/advisories/new)
(`Security` tab, `Advisories`, `Report a vulnerability`), not in a public issue. This opens a
private discussion until a fix is released.

Please include the library version, your router model and SRM version, and how to reproduce it.
Do not include passwords, session ids or unredacted router output.

## Supported versions

Only the [latest release](https://github.com/eizedev/aiosynologysrm/releases/latest) receives
fixes.

## What to expect

This is a community-maintained project without a service level. Reports are read and taken
seriously; confirmed vulnerabilities are fixed and released as soon as practical.
