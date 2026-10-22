# Static inventory of the pinned target (U5, preparation only)

Recorded 2026-10-21. Source: three lockfiles read with `git show` from commit `9f036541cf95e896db065e0c652afb75627b03c2` of
the target repository. Nothing was installed, built, scanned or looked up.

What this is: a list of declared dependencies at the pin. What it is not: the deployed build, an advisory match, or any
statement about exploitability. No vulnerability database was queried, because Gate A0 (the advisory lookup) is not approved. The
ledger rows A06 and LLM05 keep their status and gain no `target` evidence.

| File at the pin | sha256 | Declared entries |
| --- | --- | --- |
| `composer.lock` | `b6c61df767754ff419356e3be935dd7f4b7f110f0f4107b612336fe625dccd90` | 187 packages, 61 dev packages |
| `package-lock.json` | `f1a2ae48204683b38c64c15dbee4616d263e94a29df27857c80f5d57d79edb7e` | 1186 entries, 264 of them not dev |
| `agent/requirements.txt` | `d41a398e848fb75ffba3364277fb4ae4df4132ed44bba3e8c34bbdd3fce47848` | 12 lines, every one pinned with `==` |

The full list is in [target-pin-inventory.json](target-pin-inventory.json).

Limits worth knowing:
- The agent code is private and the agent is not reachable from the public tunnel. Its requirements file says what is declared,
  not what is installed in the running image.
- `composer.lock` and `package-lock.json` describe the OpenEMR application as shipped upstream plus this fork's changes. Many
  entries are build or test tooling and never run on the server.
- To add advisory matches later, Gate A0 needs your approval first. The result would be dated, because advisories change.
