# AGENTS.md

Instructions for AI coding agents working on this repository. People should read
[CONTRIBUTING.md](CONTRIBUTING.md) first; this file adds what an agent tends to get wrong.

## What this is

An async, read-only Python client for the Synology Router Manager (SRM) Web API. It is a library
for others (Home Assistant integrations, scripts), so its public API, error types and docs are a
contract.

## Commands

```sh
uv sync                       # environment from uv.lock
uv run pytest                 # tests, including property-based tests (Hypothesis)
uv run pytest --cov           # coverage must stay at 100 %
uv run ruff check . && uv run ruff format --check .
uv run mypy                   # strict
```

## Rules that matter here

- **Read-only.** New calls go into `src/aiosynologysrm/reads.py` and must use a read method
  (`get`, `list`, `info`, `tablesget`). Never add a method that changes router settings, and never
  bypass the allowlist through `_post`. `tests/test_robustness.py::test_allowlist_is_pinned` lists
  every allowed call on purpose: update it in the same change, so a reviewer sees it.
- **Every new API needs a fixture** recorded on a real router and anonymized with
  `scripts/anonymize.py` (all files of one recording in one run). Never commit raw router output;
  `*.raw.json` is ignored for that reason. Check the anonymized output by eye: the script cannot
  know every field that may be personal.
- **Parsers never raise.** Use the converters in `_parse.py` (`to_int`, `to_str`, `to_bool`,
  `to_timedelta`, ...). Add the new parser to `PARSERS` in `tests/test_robustness.py`.
- **Units only when verified** on a router; otherwise keep SRM's number in a field ending in `_raw`.
- **Errors never carry secrets**: no URL, password, session id or response body in an exception or
  log message.
- **Docs describe the current state**: update `README.md`, `docs/compatibility.md` and
  `CHANGELOG.md` (Keep a Changelog, under `[Unreleased]`) in the same change.
- Commit messages follow Conventional Commits.

## Don'ts

- Don't log in to real routers from tests; use the fake server in `tests/conftest.py`.
- Don't widen dependency ranges or add dependencies without a reason in the pull request.
- Don't edit generated files: `src/aiosynologysrm/_version.py`, `uv.lock` by hand.
