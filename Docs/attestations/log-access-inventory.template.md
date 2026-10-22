# Log-access inventory TEMPLATE (R7, section 6)

Unfilled on purpose. Copy to `Docs/attestations/log-access-inventory.md` after Gate A and fill it in by hand. It is
operator-attested, not independently verified. Record roles and locations only, never a credential, token or cookie.

The public target is a shared, internet-reachable endpoint. Anyone with the URL can send it traffic, so the window's
access log is the only evidence of who else reached it. Review the log before and after every window. An entry you
cannot explain means stop, rotate the fixture credential and close the tunnel.

| Item | Value |
| --- | --- |
| Operator | |
| Access log location (path or service, not contents) | |
| Who can read it | |
| Retention | |
| Reviewed before window (date, by whom) | |
| Reviewed after window (date, by whom) | |
| Unexplained entries | |
| Tunnel or edge in front of the target (name only) | |
| Edge-side rate or access controls in force | |
