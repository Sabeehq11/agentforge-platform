"""R7-R8 offline gate validators.

Pure functions over local files and plain values. Nothing here opens a socket, runs a process, reads a secret
or an environment variable, opens `.env`, or opens a database. A validator never produces evidence: it only judges
a record that a human supplied, and an unfilled template always fails. Passing a validator is not R7 or R8
acceptance (plan section 4b). The AST test in tests/test_r7_r8_offline.py enforces the import rules.
"""
