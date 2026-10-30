"""Check a release tag against the built package and print its notes from CHANGELOG.md.

    python3 scripts/release_notes.py v0.9.0 dist > notes.md
    python3 scripts/release_notes.py --check dist     # CI: only the built files, any version

Fails when the tag is not of the form vX.Y.Z, when a file in the dist directory was built with
another version (hatch-vcs takes it from git, so a tag on the wrong commit shows up here), or when
CHANGELOG.md has no section for the version, so a release cannot go out with a wrong version or
without notes. Standard library only: the release workflow runs it with the runner's Python.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
CHANGELOG = ROOT / "CHANGELOG.md"
DOCS = "https://aiosynologysrm.eize.dev/"
# aiosynologysrm-0.9.0-py3-none-any.whl, aiosynologysrm-0.9.0.tar.gz
_DIST = re.compile(r"^aiosynologysrm-(?P<version>[^-]+?)(?:-.+\.whl|\.tar\.gz)$")


class ReleaseError(Exception):
    """The tag, the built files and the changelog do not agree."""


def section(changelog: str, version: str) -> str:
    """Return the body of the changelog's section for a version, without its heading."""
    heading = re.compile(rf"^## \[{re.escape(version)}\][^\n]*\n", re.MULTILINE)
    match = heading.search(changelog)
    if match is None:
        raise ReleaseError(f"CHANGELOG.md has no section [{version}]")
    rest = changelog[match.end() :]
    end = re.search(r"^## |^\[[^\]]+\]: ", rest, re.MULTILINE)
    body = (rest[: end.start()] if end else rest).strip()
    if not body:
        raise ReleaseError(f"The section [{version}] of CHANGELOG.md is empty")
    return body


def built_versions(names: list[str]) -> set[str]:
    """Return the versions in the names of built files; other files are not expected.

    Hidden files are left out: uv writes a ``.gitignore`` into the dist directory, and
    upload-artifact skips hidden files, so they never reach PyPI.
    """
    versions = set()
    for name in names:
        if name.startswith("."):
            continue
        match = _DIST.match(name)
        if match is None:
            raise ReleaseError(f"Unexpected file in the dist directory: {name}")
        versions.add(match["version"])
    if not versions:
        raise ReleaseError("The dist directory has no built files")
    return versions


def notes(tag: str, dist_files: list[str], changelog: str) -> str:
    """Return the release notes for a tag, after checking it against the built files."""
    version = tag.removeprefix("v")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version) or tag != f"v{version}":
        raise ReleaseError(f"{tag} is not a tag of the form vX.Y.Z")
    built = built_versions(dist_files)
    if built != {version}:
        raise ReleaseError(f"{tag} does not match the built version {', '.join(sorted(built))}")
    return f"{section(changelog, version)}\n\nDocumentation: {DOCS}\n"


def main(argv: list[str]) -> int:
    """Print the notes for the tag and dist directory in argv, or the reason there are none."""
    if len(argv) != 3:  # noqa: PLR2004 - the script, the tag or --check, the dist directory
        print(__doc__, file=sys.stderr)
        return 2
    files = sorted(p.name for p in Path(argv[2]).iterdir() if p.is_file())
    try:
        if argv[1] == "--check":
            versions = built_versions(files)
            if len(versions) != 1:
                raise ReleaseError(f"The built files disagree: {', '.join(sorted(versions))}")
            print(f"Built version {versions.pop()}: the release check accepts these files")
        else:
            print(notes(argv[1], files, CHANGELOG.read_text(encoding="utf-8")), end="")
    except ReleaseError as err:
        print(err, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
