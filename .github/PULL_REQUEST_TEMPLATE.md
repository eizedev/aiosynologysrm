## Summary

<!-- What does this change, and why? -->

## Test plan

<!-- How did you verify it? Name the router model and SRM version if you tested on a device. -->

- [ ] `uv run pytest`, `uv run mypy`, `uv run ruff check .` pass
- [ ] New API calls are reads only and listed in `reads.py`
- [ ] New fixtures are anonymized and checked by eye
- [ ] No personal data (addresses, host names, network layout) in code, docs or fixtures
- [ ] Breaking changes are marked as such in `CHANGELOG.md`
- [ ] `CHANGELOG.md` and, if relevant, `docs/compatibility.md` updated
