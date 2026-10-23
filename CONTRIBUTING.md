# Contributing

Use Node.js 24 or newer, with `gpgv` or `gpg` available for signature tests.
Run `npm test` before submitting a change. Tests must work without contacting
Torisim or any other public service; use synthetic data and loopback fixtures.

For a changed check, include a test that would fail under the previous
behavior. Explain what the result establishes and where it can miss a case.
Keep the CLI read-only and its runtime dependency list empty.

Never add private keys, credentials, live order records, recovery material,
activation codes, infrastructure exports or internal business documents.
Public keys and signed public statements are welcome when their provenance
and trust boundary are documented. Preserve signed bytes exactly.

Use [the security reporting process](SECURITY.md) for vulnerabilities.
