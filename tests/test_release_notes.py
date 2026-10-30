"""The release notes come from CHANGELOG.md, and a tag must match the built package."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).parents[1]


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "release_notes", ROOT / "scripts/release_notes.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["release_notes"] = module
    spec.loader.exec_module(module)
    return module


release = _load()

CHANGELOG = """# Changelog

## [Unreleased]

## [0.9.0] - 2026-10-30

### Fixed

- Something.

## [0.8.0] - 2026-10-26

- Older.

[Unreleased]: https://example.invalid/compare/v0.9.0...HEAD
[0.9.0]: https://example.invalid/compare/v0.8.0...v0.9.0
"""
# As uv build writes them, with its .gitignore (measured with uv 0.13.5).
BUILT = [".gitignore", "aiosynologysrm-0.9.0-py3-none-any.whl", "aiosynologysrm-0.9.0.tar.gz"]


def test_notes_are_the_versions_section_with_the_docs() -> None:
    text = release.notes("v0.9.0", BUILT, CHANGELOG)
    assert text.startswith("### Fixed\n\n- Something.")
    assert "Older" not in text
    assert "example.invalid" not in text
    assert text.endswith(f"Documentation: {release.DOCS}\n")


def test_the_last_section_ends_at_the_links() -> None:
    assert release.section(CHANGELOG, "0.8.0") == "- Older."


@pytest.mark.parametrize(
    ("tag", "files", "changelog", "message"),
    [
        ("0.9.0", BUILT, CHANGELOG, "not a tag"),
        ("v0.9", BUILT, CHANGELOG, "not a tag"),
        ("v0.9.0", ["aiosynologysrm-0.9.1.dev3+g1234567.tar.gz"], CHANGELOG, "built version"),
        ("v0.9.0", [*BUILT, "aiosynologysrm-0.8.0.tar.gz"], CHANGELOG, "built version"),
        ("v0.9.0", [], CHANGELOG, "no built files"),
        ("v0.9.0", [".gitignore"], CHANGELOG, "no built files"),
        ("v0.9.0", ["notes.md"], CHANGELOG, "Unexpected file"),
        ("v0.9.0", BUILT, "# Changelog\n", "no section"),
        ("v0.9.0", BUILT, "## [0.9.0] - 2026-10-30\n\n## [0.8.0]\n", "is empty"),
    ],
)
def test_mismatches_stop_the_release(
    tag: str, files: list[str], changelog: str, message: str
) -> None:
    with pytest.raises(release.ReleaseError, match=message):
        release.notes(tag, files, changelog)


def test_main(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    for name in BUILT:
        (tmp_path / name).write_text("", encoding="utf-8")
    assert release.main(["release_notes.py"]) == 2
    assert release.main(["release_notes.py", "v0.0.1", str(tmp_path)]) == 1
    assert "does not match" in capsys.readouterr().err
    (tmp_path / "aiosynologysrm-0.9.0-py3-none-any.whl").unlink()
    (tmp_path / "aiosynologysrm-0.9.0.tar.gz").unlink()
    version = _released_version()
    for name in (f"aiosynologysrm-{version}-py3-none-any.whl", f"aiosynologysrm-{version}.tar.gz"):
        (tmp_path / name).write_text("", encoding="utf-8")
    assert release.main(["release_notes.py", f"v{version}", str(tmp_path)]) == 0
    assert "Documentation:" in capsys.readouterr().out


def _released_version() -> str:
    """The newest version with a section in the real CHANGELOG.md."""
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    import re  # noqa: PLC0415

    match = re.search(r"^## \[(\d+\.\d+\.\d+)\]", text, re.MULTILINE)
    assert match is not None
    return match[1]


def test_check_accepts_one_version_of_any_kind(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    for name in (".gitignore", "aiosynologysrm-0.9.1.dev2+g1234567.tar.gz"):
        (tmp_path / name).write_text("", encoding="utf-8")
    assert release.main(["release_notes.py", "--check", str(tmp_path)]) == 0
    assert "0.9.1.dev2+g1234567" in capsys.readouterr().out
    (tmp_path / "aiosynologysrm-0.9.0.tar.gz").write_text("", encoding="utf-8")
    assert release.main(["release_notes.py", "--check", str(tmp_path)]) == 1
    assert "disagree" in capsys.readouterr().err


def test_subdirectories_and_links_are_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "aiosynologysrm-0.9.0.tar.gz").write_text("", encoding="utf-8")
    (tmp_path / "extra").mkdir()
    assert release.main(["release_notes.py", "--check", str(tmp_path)]) == 1
    assert "Only built files" in capsys.readouterr().err
    (tmp_path / "extra").rmdir()
    (tmp_path / "aiosynologysrm-0.9.0-py3-none-any.whl").symlink_to(tmp_path / "elsewhere")
    assert release.main(["release_notes.py", "--check", str(tmp_path)]) == 1
    assert "aiosynologysrm-0.9.0-py3-none-any.whl" in capsys.readouterr().err
