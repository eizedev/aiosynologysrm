# Contributing

Thanks for helping. The most useful contribution is often a report from a router model or
firmware that is not tested yet.

## Reporting a model or firmware

Open an issue with the **Model or firmware report** form and tell us the model, the SRM version
(Control Panel, Info Center) and the mode (router, mesh point, standalone access point). Never
paste raw router output: it contains your MAC addresses, IP addresses and device names. A
diagnostics command that produces an anonymized report is planned.

## Development setup

You need [uv](https://docs.astral.sh/uv/) and Python 3.12 or newer.

```sh
git clone https://github.com/eizedev/aiosynologysrm.git
cd aiosynologysrm
uv sync
uv run pytest
```

Before opening a pull request, all of these must pass (CI runs the same):

```sh
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest --cov
```

## Rules for changes

- **Read-only stays read-only.** New calls go into `src/aiosynologysrm/reads.py` and must be
  reads. Pull requests that add a call which changes router settings are not accepted.
- **Every new API needs a fixture** from a real router, anonymized with
  `python scripts/anonymize.py <raw.json> tests/fixtures/<model>-srm-<version>/<name>.json`.
  The script refuses to write a file that still contains an original value; check the output by
  eye as well before committing.
- **Units only when verified.** Name a field `_percent`, `_kib`, `_mbps` etc. only if you checked
  the unit on a router; otherwise keep SRM's number and end the name in `_raw`.
- Update [docs/compatibility.md](docs/compatibility.md) and [CHANGELOG.md](CHANGELOG.md).
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, ...).

## Releases

Maintainers tag `vX.Y.Z` on `main`. The release workflow tests, builds, publishes to PyPI via
trusted publishing and creates the GitHub release. No tokens are stored in the repository.
