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

You need [uv](https://docs.astral.sh/uv/) 0.13 and Python 3.12 or newer. `pyproject.toml` pins
uv to 0.13.x (`[tool.uv] required-version`), because CI reads the version from there and
`uv.lock` must not change between uv versions; another uv refuses to run in this repository.
Install 0.13 (`uv self update 0.13.5`, or `pipx install uv==0.13.5`); a change of the pin comes
as a pull request of its own, together with the lock file.

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
- `tests/test_privacy.py` fails on MAC and IP addresses that may be real, in the files and in
  every line your unpushed commits add. Run the tests before you push: removing an address in a
  later commit leaves it in the history, so fix the commit that added it instead.
- **Models mirror SRM.** Name fields after SRM's keys (snake_case, see docs/design.md, "Data
  model"), keep SRM's units and formats, and put anything derived into `helpers.py`. Document a
  unit in the field's docstring only if you checked it on a router.
- Update [docs/compatibility.md](docs/compatibility.md), the other pages in `docs/` where they
  describe what you changed, and [CHANGELOG.md](CHANGELOG.md). `docs/` is the website at
  https://aiosynologysrm.eize.dev/.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, ...).

## Releases

Maintainers first merge a pull request that turns `[Unreleased]` in `CHANGELOG.md` into
`[X.Y.Z] - date` (with its compare link at the bottom), then tag `vX.Y.Z` on `main`. The release
workflow runs the full CI, builds, checks with `scripts/release_notes.py` that the built version is
the tag's and that the CHANGELOG has its section, publishes to PyPI via trusted publishing and
creates the GitHub release with that section as its notes. No tokens are stored in the repository.

If a release fails after PyPI accepted it (the GitHub release job failed), use **Re-run failed
jobs**: the built files are kept and nothing is uploaded twice. **Re-run all jobs** builds again,
and the upload then fails because PyPI already has the version. If PyPI took only one of the two
files, publish the next patch version instead; a version on PyPI cannot be replaced, only yanked.
The build requirements are pinned with hashes in `build-constraints.txt`; refresh them with

```sh
printf 'hatchling>=1.27\nhatch-vcs>=0.4\n' | uv pip compile - --generate-hashes --python-version 3.12 --no-header -o build-constraints.txt
```

and put the two comment lines at the top back. Do this before each release; Dependabot does not
update this file.
