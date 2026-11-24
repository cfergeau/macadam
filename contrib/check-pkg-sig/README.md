# check-pkg-sig

Verify the code signature of a macOS flat installer package (`.pkg`) on
Linux — the offline equivalent of `pkgutil --check-signature`, without
needing a Mac. Requires only `python3` and `openssl` (3.x recommended).

This is useful when building or reviewing release artifacts from Linux CI:
it proves a `.pkg` was signed by a real Developer ID Installer certificate
chaining to Apple's root CAs, and that nothing in it was modified afterwards.

## Usage

```console
$ ./fetch-apple-roots.sh   # once: download Apple root CAs into apple-roots.pem
$ ./pkg_sig_check.py file.pkg --roots apple-roots.pem --deep --check-time
```

Checks performed, in order:

1. **TOC checksum** — the package manifest is intact
2. **every signature, cryptographically** — `openssl cms` / `openssl dgst`
3. **the signer's chain of trust** — against the Apple roots
4. `--deep`: **every file's archived checksum** — payload integrity

Exit codes: `0` all checks passed, `1` a check failed, `2` signature valid
but chain not verified (e.g. no `--roots` given).

Options:

- `--roots ROOTS.pem` — trusted root CA bundle; without it, signatures are
  checked but the chain of trust is not.
- `--deep` — also re-hash every file listed in the TOC (see caveats below;
  recommended).
- `--check-time` — enforce certificate validity periods (ignored by default,
  so old packages with expired certs still verify).
- `--untrusted CAS.pem` — extra intermediate CAs, for packages that do not
  embed their own chain.

## How a .pkg is signed

A flat package is a XAR archive:

```
[ 28-byte big-endian header ]
[ zlib-compressed XML table of contents (TOC) ]
[ heap: TOC-checksum blob, signature blobs, file data, ... ]
```

The XML TOC describes everything:

| TOC element | meaning |
|---|---|
| `<checksum style="sha1\|sha256\|...">` | hash of the compressed TOC, stored in the heap |
| `<signature style="X509">` | classic style: detached CMS/PKCS#7 blob signing the stored TOC checksum |
| `<signature style="RSA">` | legacy raw RSA PKCS#1 v1.5 over `<toc-style>(compressed TOC)` — i.e. over the TOC checksum; signer cert in an embedded xmldsig `<KeyInfo>` |
| `<x-signature style="CMS">` | newer style: detached CMS signing the stored TOC checksum, usually carrying the full certificate chain and an RFC 3161 timestamp token |
| `<file>/<archived-checksum>` | per-file hashes over heap bytes |

Packages signed by recent `productbuild`/`productsign` carry **both** an RSA
and a CMS signature; older packages only have `X509`. All styles are
verified.

## Caveats worth knowing

- **The package signature only covers the TOC, not the payload.** Payload
  integrity comes from the per-file checksums listed in the TOC — always
  pass `--deep`. (macOS Installer checks those same per-file checksums at
  install time.) Flipping a single byte inside `Payload` leaves both
  signatures valid; only `--deep` catches it.
- **Apple certificate quirks**, handled automatically by the script:
  Apple uses a private EKU OID, so OpenSSL needs `-purpose any`; Apple marks
  a private extension (`1.2.840.113635.100.6.1.14`) critical, so OpenSSL
  needs `-ignore_critical` — plain `openssl verify` fails with "unhandled
  critical extension"; and the `openssl cms` app has no `-untrusted` option,
  so embedded certificates are pooled and passed to `openssl verify`
  separately.
- **Notarization cannot be verified offline.** That requires Apple's
  Gatekeeper service. On a Mac, `pkgutil --check-signature` reports it, and
  `spctl --assess --type install` performs the full Gatekeeper evaluation.
  Everything else — signatures, signing time, timestamp token, chain of
  trust, payload hashes — is verified locally here.
- The RFC 3161 timestamp token embedded in `x-signature` blobs is detected
  and reported, but not verified against Apple's Timestamp CA.

## Example

```console
$ ./pkg_sig_check.py macadam-installer-macos-universal.pkg \
      --roots apple-roots.pem --deep --check-time
Package:      macadam-installer-macos-universal.pkg
  size:       82,324,069 bytes
  TOC:        4,906 B compressed, 18,018 B XML (xar v1)
  TOC checksum: OK (sha1) — manifest intact
  signature #1: signature[RSA] (256 bytes)
    signer:     UID=HYSCB8KRL2, CN=Developer ID Installer: Red Hat, Inc. (HYSCB8KRL2), OU=HYSCB8KRL2, O=Red Hat, Inc., C=US
    issued by:  CN=Developer ID Certification Authority, OU=Apple Certification Authority, O=Apple Inc., C=US
    validity:   Apr 18 20:07:25 2022 GMT .. Feb  1 22:12:15 2027 GMT
    crypto:     VALID — RSA-sha1 over the TOC checksum
    chain:      VERIFIED against apple-roots.pem
  signature #2: x-signature[CMS] (9,216 bytes)
    signer:     UID=HYSCB8KRL2, CN=Developer ID Installer: Red Hat, Inc. (HYSCB8KRL2), OU=HYSCB8KRL2, O=Red Hat, Inc., C=US
    issued by:  CN=Developer ID Certification Authority, OU=Apple Certification Authority, O=Apple Inc., C=US
    validity:   Apr 18 20:07:25 2022 GMT .. Feb  1 22:12:15 2027 GMT
    certs:      3 embedded in CMS
    signed at:  2026-11-17 20:00:34 UTC
    timestamp:  RFC 3161 token embedded (trusted signing time)
    crypto:     VALID — CMS over the TOC checksum
    chain:      VERIFIED against apple-roots.pem
  payload:    7 files checked, 0 checksum mismatch(es)

Status: SIGNED, all signatures valid, chain of trust VERIFIED
        (pkgutil equivalent: 'signed by a certificate trusted by macOS')
```
