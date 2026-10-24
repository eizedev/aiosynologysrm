# Contributing

Thanks for helping. The most useful contribution is often a report from a router model or
firmware that is not tested yet.

## Reporting a model or firmware

Open an issue with the **Model or firmware report** form and tell us the model, the SRM version
(Control Panel, Info Center) and the mode (router, mesh point, standalone access point). Never
paste raw router output: it contains your MAC addresses, IP addresses and device names. Instead,
run the diagnostics command and paste its output; it describes what the router answers without
any of the values:

```sh
pip install aiosynologysrm
aiosynologysrm-diagnostics <router address> --user <admin account>
```

## Where help is wanted

Issues labelled [`help wanted`](https://github.com/eizedev/aiosynologysrm/labels/help%20wanted)
need someone with hardware or a setup the maintainer does not have, for example a mesh. Issues
labelled [`roadmap`](https://github.com/eizedev/aiosynologysrm/labels/roadmap) describe what is
planned next. Other labels:

| Label | Meaning |
| --- | --- |
| `bug` | something does not work as documented |
| `enhancement` | something the library should read or do |
| `compatibility` | a report about a model, firmware or setup |
| `needs device test` | implemented, but not checked on a real device yet |
| `breaking change` | changes the public API |
| `security` | a security-relevant change (report vulnerabilities privately, see SECURITY.md) |
| `documentation` | docs only |
| `dependencies` | dependency updates, usually from Dependabot |

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
  The script refuses to write anything when a text field is not classified yet (add it to one of
  its lists) or an original value is left; check the output by eye as well before committing.
- **Units only when verified.** Name a field `_percent`, `_kib`, `_mbps` etc. only if you checked
  the unit on a router; otherwise keep SRM's number and end the name in `_raw`.
- Update [docs/compatibility.md](docs/compatibility.md) and [CHANGELOG.md](CHANGELOG.md).
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, ...).

## Releases

Maintainers tag `vX.Y.Z` on `main`. The release workflow tests, builds, publishes to PyPI via
trusted publishing and creates the GitHub release. No tokens are stored in the repository.
