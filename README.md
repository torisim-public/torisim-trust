# Torisim trust checks

**Private by proof, not by promise.**

Run a standalone version of Torisim's website privacy checks, inspect what
they test, and verify copies of our published signed files. This repository
contains the checker, tests, and four public verification files.

A passing result covers the checks listed below. It does not prove how the
server handles an order, what data a carrier retains, or that the running
website uses any particular source code. This is not an independent audit.

## Start here

Use Node.js 24 or newer. Signature verification also needs `gpgv` or `gpg` on
your PATH. There are no npm dependencies and no install step.

```sh
npm test
npm run verify:files
```

Tests use synthetic fixtures, bundled public snapshots and local servers. The
second command works offline: it checks file hashes, the pinned public key,
signatures, the canary's dates, and the security contact file's expiry. It returns a failure if a
signature cannot be verified or a time-sensitive file has expired.

To check the live website, explicitly choose its HTTPS origin:

```sh
npm run check -- --base https://torisim.com
```

This makes public GET requests, including placeholder order/support paths;
the site and your network can see the requests. The referral-cookie check is
off by default. If the other checks pass, this leaves an **incomplete result
(exit 3)**. To include that check:

```sh
npm run check -- --base https://torisim.com --partner-check
```

That option adds two requests with a fixed synthetic referral code and reads
the response cookie attributes. It does not submit an order or payment.
Add `--json` for structured output. Use `--help` for all options.

## What you can check

| Material | What the result establishes |
| --- | --- |
| Website headers and fetched HTML | The listed pages returned the checked cache, indexing, CSP and cookie settings, and passed the static third-party-reference rules at the time of the request. |
| `public/pgp.txt` | The key has the expected fingerprint and contains one primary public key. |
| `public/canary.txt` | The canary has a valid signature from that key and its signed dates are within the checker's limits. |
| `public/mirrors.txt` | The mirror list has a valid signature from that key. |
| `public/security.txt` | The unsigned contact file has the expected fields and a future expiry. Source comments have been removed. |
| `public/manifest.json` | The bundled files match their recorded SHA-256 hashes. The unsigned manifest records capture metadata and any transformation. |

The checker reads response headers and HTML. It does **not** execute JavaScript,
inspect browser network traffic, or inspect server logs. Allowed Stripe and
Cloudflare origins reflect the public website policy; a pass does not mean
there are no third parties. See [the exact checks and limits](docs/checks.md).

## Public key and snapshots

Expected fingerprint:

```text
4F8F 4622 F3A1 AB6B 82E9 61AE C9CA CCC4 2226 BA86
```

The source files were fetched from Torisim's public website on 18 October 2026.
The key, canary and mirror list are exact copies. The unsigned contact copy
omits source comments; the manifest records that change and the original hash.
The canary is dated 5 October and calls for the next canary by 4 November 2026
(UTC). These are dated snapshots: they will become stale. Fetch newer files
from the URLs in the manifest and verify them before relying on them.

Obtain the expected fingerprint through a channel you trust. A repository
containing both a key and its expected fingerprint cannot establish trust in
that key by itself. A valid signature authenticates the signed statement; it
does not independently establish that the statement is true.

Read [verification instructions](docs/verification.md) for the trust boundary
and file format. The code is MIT licensed; see [LICENSE](LICENSE).

Report vulnerabilities privately using [SECURITY.md](SECURITY.md). General
contributions and test guidance are in [CONTRIBUTING.md](CONTRIBUTING.md).
