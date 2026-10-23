# Verify the public files

Run `npm run verify:files` from the repository directory. It reads only the
bundled files and invokes local GnuPG; it makes no network requests. Add
`-- --json` for a structured report.

The verifier requires exactly the four expected files and their manifest in
`public/`, rejects symbolic links and oversized files, and checks each file's
recorded size and SHA-256 hash. The manifest contains the public source URL
and capture timestamp for each file. It is an unsigned inventory: someone
who changes a file can also change its hash. Hashes detect an unexpected
change relative to that inventory; they do not establish its author's identity.
The unsigned security contact copy has its source comments removed. Its
manifest entry records that transformation and the original source hash;
the offline command checks the bundled copy's hash. The public key and both
signed statements are preserved exactly.

For authenticity, the verifier checks that `pgp.txt` contains one primary key
with the fingerprint pinned in the source. It then verifies `canary.txt` and
`mirrors.txt` with that key in an isolated temporary GnuPG directory. The
canary's dates are read only from verified plaintext. Future issue dates,
duplicate date fields, an age over 31 days and a passed next-canary deadline
fail verification. The next-canary day runs through its end in UTC.

`security.txt` is unsigned. Its contact, encryption-key URL, canonical URL
and expiry are checked as contact-file metadata. This does not turn it into
a signed statement. The mirror list is signed but has no expiry policy in
this verifier; its capture and signed issue dates remain relevant to readers.

The dated canary will eventually fail the freshness check. That does not
invalidate its historical signature. Use the current files at
[Torisim's public key](https://torisim.com/pgp.txt),
[canary](https://torisim.com/canary.txt),
[mirror list](https://torisim.com/mirrors.txt) and
[security contact](https://torisim.com/.well-known/security.txt) for a current
assessment. The website checker fetches those URLs and verifies against the
bundled key. It never silently trusts a new key supplied by the website.

## What you must trust

You must obtain the checker and expected fingerprint from sources you trust,
and trust your local Node.js/GnuPG binaries and clock. This repository cannot
bootstrap its own authenticity. Key rotation needs a separately reviewed
change; a newly downloaded key is not accepted just because it came from the
same website as a signature.

The signatures authenticate published statements. They cannot independently
prove the absence of a legal demand, the identity of a network operator, or
the behavior of Torisim's running systems.

## Source and fixtures

The checker was extracted from Torisim's website-checking tool and hardened
for standalone use. This repository's source is the version to review for
these commands; it is not an attestation of a server deployment.

Signed test fixtures use synthetic `.invalid` identities and generic labels.
Their temporary signing keys are not included. They are separate from the
Torisim public key and its signed statements.
