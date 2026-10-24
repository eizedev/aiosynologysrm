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
  `*.raw.json` is ignored for that reason. The script is an allowlist: a new text field stops it
  until the field is added to `KEEP_VALUES`, `KEEP_PATTERNS`, `ADDRESS_KEYS`, `NAME_KEYS`,
  `NUMBER_KEYS` or `CONTAINER_KEYS`. Keep only fixed
  vocabulary; when in doubt, it is a name. Check the output by eye as well.
- **Models mirror SRM** (docs/design.md, "Data model"): frozen dataclasses deriving from
  `SrmModel`, one per SRM object, every field declared as `name: T = srm("srmKey", converter)`
  with `name == snake("srmKey")`, then `raw: Mapping[str, Any] = raw_field()`. No renaming, no
  interpretation in models; derived values go into `helpers.py`.
- **Parsers never raise.** Use the converters in `_parse.py` (`to_int`, `to_str`, `to_bool`,
  `to_timedelta`, ...). Every exported model is fuzzed by `tests/test_robustness.py` automatically.
- **Units only when verified** on a router, and then in the field's docstring, not its name.
- **Errors never carry secrets**: no URL, password, session id or response body in an exception or
  log message.
- **Docs describe the current state**: update the pages in `docs/` (the website), `README.md`
  when the quick start or the device list changes, and `CHANGELOG.md` (Keep a Changelog, under
  `[Unreleased]`) in the same change.
- **Website**: `docs/` and `zensical.toml`, built by `.github/workflows/docs.yml` with the shared
  design from eizedev/brand (`docs-site/`); `docs/assets/site.css` is copied in at build time and
  not committed. Preview: see "Documentation websites" in eizedev/brand's README.
- Commit messages follow Conventional Commits.

## Don'ts

- Don't log in to real routers from tests; use the fake server in `tests/conftest.py`.
- Don't widen dependency ranges or add dependencies without a reason in the pull request.
- Don't edit generated files: `src/aiosynologysrm/_version.py`, `uv.lock` by hand.
