# Checks and limits

The website checker makes GET requests to six public pages, ten private-route
placeholders, three signed-file endpoints and `/.well-known/security.txt`.
The public/private grouping describes expected response policy; the checker
does not log in or retrieve a real order. Route lists are exported at the top
of `src/privacy-check.mjs` so readers can inspect the exact scope.

It checks response policy including CSP, caching, indexing, referrer and
permissions headers; scans HTML for third-party resource references; checks
that public page responses do not set cookies; verifies the public key and
signed files; checks canary dates; and checks the security contact file.
The optional referral test checks cookie flags and lifetime on two responses.
Each result has an ID and an explanation in text or JSON output.

The CSP policy permits named Stripe and Cloudflare origins and inline scripts.
An allowed source is not a claim that every script from that source is safe.
The HTML scanner is a bounded static check, not a full browser parser. It
does not load scripts, stylesheets, frames or images, follow links, or observe
requests made by JavaScript. Browser-injected analytics and delayed network
requests can therefore fall outside its view. A browser network audit is a
separate task.

The checker cannot establish server-side data retention, payment privacy,
carrier behavior, legal-demand history, or the truth of a signed canary.
Missing checks remain visible as skipped results. A failing check needs
investigation; it is not automatically an exploitable vulnerability.

## Network and process boundaries

The CLI requires an explicit origin. Remote targets use HTTPS; literal
loopback HTTP is allowed for tests. Credentials, paths, queries and fragments
in the base URL are rejected. Redirects are refused. Responses have a 2 MiB
limit, requests have timeouts, and a failed fetch is retried once. The checker
does not reuse browser cookies or a browser session.

Run this as a local CLI with a target you choose. Do not expose it as a web
service accepting arbitrary URLs: HTTPS alone does not prevent access to a
private address or DNS rebinding. Requests to a chosen site can be logged by
that site and network intermediaries.

GnuPG runs with a temporary keyring and home directory, bounded output and a
timeout. It does not use your personal keyring or fetch signing keys. Canary
dates are read from the plaintext produced by successful verification.
Only public keys are shipped. Use an up-to-date Node.js and GnuPG installation.

## Exit status

| Code | Website checker result |
| --- | --- |
| 0 | Every enabled check passed, with no skipped checks. |
| 1 | At least one check failed. |
| 2 | Invalid CLI input or an execution error. |
| 3 | No check failed, but at least one was skipped. |

The referral check is opt-in, so a default run can return 3 even when all its
other checks pass. Disabling signature verification also leaves the run
incomplete. Neither case is a complete pass.

The offline verifier returns 0 only when all its checks pass, 1 when
verification fails (including missing GnuPG), and 2 for invalid CLI input.
