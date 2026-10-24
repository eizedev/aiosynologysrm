# Diagnostics

`aiosynologysrm-diagnostics <router> --user <admin>` (or `python -m aiosynologysrm.diagnostics`)
prints a JSON report to paste into an issue. It contains exactly this:

- library version, router model, SRM version, operating mode
- whether the WAN IPv4 address is `public`, `private` or `cgnat` (the category, not the address)
- the minimum and maximum version of each API the library uses
- for every getter: whether it works or which error code it returned, how many items it returned
  (leave this out with `--no-counts`), the type of every field (`str`, `int`, `None`, ...) and how
  many keys SRM sent that the library does not map yet (only the number, never the names)

It contains no addresses, host names, network names or other values. GitHub issues in a public
repository are always public, so read the output before posting it. The password comes from
`SRM_PASSWORD` or a prompt; an unknown certificate is shown for confirmation. Applications can call
`aiosynologysrm.diagnostics.collect_diagnostics(client)`.

When a value itself matters, for example a field the library parses wrongly, turn the raw answer
into a fixture with `scripts/anonymize.py` (see [CONTRIBUTING.md](https://github.com/eizedev/aiosynologysrm/blob/main/CONTRIBUTING.md)) and attach that.
