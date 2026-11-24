#!/usr/bin/env python3
"""
pkg_sig_check.py - verify the signature of a macOS flat package (.pkg) on Linux.

A .pkg is a XAR archive:

    [ 28-byte big-endian header ]
    [ zlib-compressed XML table of contents (TOC) ]
    [ heap: TOC-checksum blob, signature blobs, file data, ... ]

The TOC describes:
  <checksum style="sha1|sha256|...">  hash of the compressed TOC, stored in
                                       the heap
  <signature style="X509">            classic style: detached CMS/PKCS#7 blob
                                       signing the stored TOC checksum
  <signature style="RSA">             legacy raw RSA PKCS#1 v1.5 signature over
                                       <toc-style>(compressed TOC) == the TOC
                                       checksum; signer cert in an embedded
                                       xmldsig <KeyInfo>
  <x-signature style="CMS">           newer style: detached CMS signing the
                                       stored TOC checksum, usually carrying
                                       the full cert chain and an RFC 3161
                                       timestamp token
  <file>/<archived-checksum>          per-file hashes over heap bytes

Checks performed, in order:
  1. TOC checksum                              (manifest integrity)
  2. each signature, cryptographically         (openssl cms / openssl dgst)
  3. the signer's chain of trust               (openssl verify against a root
                                                bundle, e.g. Apple's roots)
  4. --deep: every file's archived checksum    (payload integrity — the
                                                signature only covers the TOC,
                                                so this check matters!)

Apple-package quirks this script works around:
  - Apple's private EKU OID          -> openssl needs -purpose any
  - critical private Apple extension -> openssl needs -ignore_critical
  - the `cms` app has no -untrusted  -> embedded certs are pooled and passed
                                        to `openssl verify` separately

Only python3 + openssl are required.  Run ./fetch-apple-roots.sh once to
download Apple's root certificates into apple-roots.pem (they are also
available from https://www.apple.com/certificateauthority/).

Usage:
  ./pkg_sig_check.py FILE.pkg [--roots ROOTS.pem] [--untrusted CAS.pem]
                             [--deep] [--check-time]

Exit codes: 0 = all checks passed, 1 = a check failed,
            2 = signature valid but chain not verified.
"""
import argparse
import hashlib
import os
import re
import struct
import subprocess
import sys
import tempfile
import zlib
from datetime import datetime
import xml.etree.ElementTree as ET

XAR_MAGIC = 0x78617221  # 'xar!'


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace")


def read_exact(f, n, what):
    b = f.read(n)
    if len(b) != n:
        sys.exit(f"error: file truncated while reading {what}")
    return b


def pem_wrap(b64):
    b64 = "".join(b64.split())
    lines = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n"


def split_certs(pem_text):
    return re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                      pem_text, re.S)


def cert_info(pem):
    """subject/issuer/validity of one certificate PEM."""
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as t:
        t.write(pem)
        p = t.name
    r = run(["openssl", "x509", "-in", p, "-noout",
             "-subject", "-issuer", "-startdate", "-enddate"])
    os.unlink(p)
    info = {"pem": pem, "path": None, "subject": "", "issuer": "", "dates": ""}
    for line in r.stdout.splitlines():
        if line.startswith("subject="):
            info["subject"] = line[8:].strip()
        elif line.startswith("issuer="):
            info["issuer"] = line[7:].strip()
        elif line.startswith("notBefore="):
            info["dates"] = line[10:].strip()
        elif line.startswith("notAfter="):
            info["dates"] += " .. " + line[9:].strip()
    return info


def find_leaf(infos):
    """the cert whose subject is not the issuer of any other cert."""
    for c in infos:
        others = [o for o in infos if o is not c]
        if c["subject"] not in {o["issuer"] for o in others}:
            return c
    return infos[0] if infos else None


def write_cert(info, path):
    with open(path, "w") as w:
        w.write(info["pem"])
    info["path"] = path
    return path


def find_keyinfo_cert(el):
    for e in el.iter():
        if e.tag.endswith("}X509Certificate") or e.tag == "X509Certificate":
            if e.text and "BEGIN CERTIFICATE" not in e.text:
                return pem_wrap(e.text)
    return None


def signing_time(sig_p):
    """(signingTime value, has RFC 3161 timestamp token) from a CMS blob."""
    r = run(["openssl", "cms", "-cmsout", "-print", "-inform", "DER", "-in", sig_p])
    txt = r.stdout
    i = txt.find("signingTime")
    if i < 0:
        return None, "timeStampToken" in txt
    m = re.compile(r"(?:UTCTIME|GENERALIZEDTIME)\s*:?\s*([^\n]+)").search(txt, i)
    raw = m.group(1).strip() if m else None
    val = raw
    if raw:
        for fmt in ("%b %d %H:%M:%S %Y %Z", "%y%m%d%H%M%SZ"):
            try:
                val = datetime.strptime(raw, fmt).strftime("%Y-%m-%d %H:%M:%S UTC")
                break
            except ValueError:
                continue
    return val, "timeStampToken" in txt


def verify_chain(leaf_path, untrusted_path, roots, check_time):
    cmd = ["openssl", "verify", "-purpose", "any", "-ignore_critical"]
    if not check_time:
        cmd.append("-no_check_time")
    cmd += ["-CAfile", roots]
    if untrusted_path:
        cmd += ["-untrusted", untrusted_path]
    cmd.append(leaf_path)
    return run(cmd)


def main():
    ap = argparse.ArgumentParser(description="verify a macOS .pkg signature")
    ap.add_argument("pkg")
    ap.add_argument("--roots", help="trusted root CA bundle (PEM)")
    ap.add_argument("--untrusted", help="extra intermediate CA bundle (PEM)")
    ap.add_argument("--deep", action="store_true",
                    help="also verify per-file archived checksums")
    ap.add_argument("--check-time", action="store_true",
                    help="enforce certificate validity times (default: ignored)")
    args = ap.parse_args()

    try:
        f = open(args.pkg, "rb")
    except OSError as e:
        sys.exit(str(e))

    hdr = read_exact(f, 28, "header")
    magic, hdrsz, version, toc_c, toc_u, _ = struct.unpack(">IHHQQI", hdr)
    if magic != XAR_MAGIC:
        sys.exit(f"{args.pkg}: not a XAR archive (not a flat .pkg)")
    heap_base = hdrsz + toc_c
    toc_raw = read_exact(f, toc_c, "TOC")
    try:
        toc_xml = zlib.decompress(toc_raw)
    except zlib.error:
        toc_xml = zlib.decompress(toc_raw, -15)
    toc = ET.fromstring(toc_xml).find("toc")
    if toc is None:
        sys.exit("error: no <toc> element found")

    print(f"Package:      {args.pkg}")
    print(f"  size:       {os.path.getsize(args.pkg):,} bytes")
    print(f"  TOC:        {toc_c:,} B compressed, {toc_u:,} B XML (xar v{version})")

    failures = []

    # ---- 1. TOC checksum (manifest integrity) -----------------------------
    ck = toc.find("checksum")
    if ck is None:
        sys.exit("error: TOC has no <checksum> element")
    ck_style = ck.get("style", "sha1")
    f.seek(heap_base + int(ck.findtext("offset")))
    stored_ck = read_exact(f, int(ck.findtext("size")), "TOC checksum")
    if stored_ck == hashlib.new(ck_style, toc_raw).digest():
        print(f"  TOC checksum: OK ({ck_style}) — manifest intact")
    else:
        print(f"  TOC checksum: FAIL ({ck_style}) — manifest modified after packaging")
        failures.append("toc")

    # ---- 2 + 3. signatures and chains of trust -----------------------------
    sig_els = toc.findall("signature") + toc.findall("x-signature")
    if not sig_els:
        print("  signature:  NONE — package is unsigned")
        failures.append("unsigned")

    sig_ok_all = True
    chain_ok_all = True

    with tempfile.TemporaryDirectory() as td:
        toc_p = os.path.join(td, "toc.compressed")
        cksum_p = os.path.join(td, "toc.cksum")
        for p, b in ((toc_p, toc_raw), (cksum_p, stored_ck)):
            with open(p, "wb") as w:
                w.write(b)

        # ---- pre-pass: read blobs, pool all available certificates ----
        pool = {}
        sigs = []
        for i, el in enumerate(sig_els):
            style = el.get("style", "X509")
            f.seek(heap_base + int(el.findtext("offset")))
            der = read_exact(f, int(el.findtext("size")), f"signature #{i + 1}")
            sig_p = os.path.join(td, f"sig{i}.der")
            with open(sig_p, "wb") as w:
                w.write(der)

            keyinfo = find_keyinfo_cert(el)
            keyinfo_info = cert_info(keyinfo) if keyinfo else None
            if keyinfo_info:
                pool.setdefault(keyinfo_info["subject"], keyinfo_info)

            embedded = []
            if style != "RSA":
                r = run(["openssl", "pkcs7", "-print_certs",
                         "-inform", "DER", "-in", sig_p])
                if r.returncode == 0:
                    embedded = [cert_info(p) for p in split_certs(r.stdout)]
                    for c in embedded:
                        pool.setdefault(c["subject"], c)

            sigs.append({"i": i, "tag": el.tag, "style": style, "sig_p": sig_p,
                         "size": len(der), "keyinfo": keyinfo_info,
                         "embedded": embedded})

        pool_p = os.path.join(td, "pool.pem")
        with open(pool_p, "w") as w:
            w.write("\n".join(c["pem"] for c in pool.values()))
        if args.untrusted and os.path.exists(args.untrusted):
            with open(args.untrusted) as r:
                extra = r.read()
            with open(pool_p, "a") as w:
                w.write("\n" + extra)

        # ---- verify each signature ----
        for s in sigs:
            kind = f"{s['tag']}[{s['style']}]"
            print(f"  signature #{s['i'] + 1}: {kind} ({s['size']:,} bytes)")

            leaf = s["keyinfo"] or (find_leaf(s["embedded"])
                                    if s["embedded"] else None)
            if leaf:
                print(f"    signer:     {leaf['subject']}")
                print(f"    issued by:  {leaf['issuer']}")
                print(f"    validity:   {leaf['dates']}")

            sig_ok = None
            chain_ok = None

            if s["style"] == "RSA":
                if not s["keyinfo"]:
                    print("    crypto:     cannot check — no signer certificate (KeyInfo)")
                    sig_ok = False
                else:
                    ki_p = write_cert(s["keyinfo"],
                                      os.path.join(td, f"ki{s['i']}.pem"))
                    pub_p = os.path.join(td, f"pub{s['i']}.pem")
                    r = run(["openssl", "x509", "-in", ki_p, "-pubkey", "-noout"])
                    with open(pub_p, "w") as w:
                        w.write(r.stdout)
                    r = run(["openssl", "dgst", f"-{ck_style}", "-verify", pub_p,
                             "-signature", s["sig_p"], toc_p])
                    sig_ok = r.returncode == 0
                    print(f"    crypto:     {'VALID' if sig_ok else 'INVALID'}"
                          f" — RSA-{ck_style} over the TOC checksum")
                    if not sig_ok and r.stderr.strip():
                        print("      " + r.stderr.strip().replace("\n", "\n      "))
            else:  # X509 (classic) / CMS (x-signature)
                signed_at, has_tst = signing_time(s["sig_p"])
                if s["embedded"]:
                    print(f"    certs:      {len(s['embedded'])} embedded in CMS")
                if signed_at:
                    print(f"    signed at:  {signed_at}")
                if has_tst:
                    print("    timestamp:  RFC 3161 token embedded "
                          "(trusted signing time)")

                cmd = ["openssl", "cms", "-verify", "-binary", "-inform", "DER",
                       "-in", s["sig_p"], "-content", cksum_p,
                       "-purpose", "any", "-ignore_critical"]
                if not args.check_time:
                    cmd.append("-no_check_time")
                cmd += ["-CAfile", args.roots] if args.roots else ["-noverify"]
                r = run(cmd)
                if r.returncode == 0:
                    sig_ok = True
                    chain_ok = bool(args.roots)
                    print("    crypto:     VALID — CMS over the TOC checksum")
                else:
                    # signature-only retry; chain handled separately below
                    if args.roots:
                        cmd = cmd[:cmd.index("-CAfile")] + ["-noverify"]
                    r2 = run(cmd)
                    sig_ok = r2.returncode == 0
                    print(f"    crypto:     {'VALID' if sig_ok else 'INVALID'}"
                          f" — CMS over the TOC checksum")
                    if not sig_ok and r2.stderr.strip():
                        print("      " + r2.stderr.strip().replace("\n", "\n      "))
                    elif sig_ok and r.stderr.strip():
                        print("    chain note: "
                              + r.stderr.strip().splitlines()[-1])

            # chain of trust, when not already established by cms -verify
            if sig_ok and args.roots and not chain_ok and leaf:
                leaf_p = leaf.get("path") or write_cert(
                    leaf, os.path.join(td, f"leaf{s['i']}.pem"))
                r = verify_chain(leaf_p, pool_p, args.roots, args.check_time)
                chain_ok = r.returncode == 0
                if not chain_ok and r.stderr.strip():
                    print("    chain:      FAILED — "
                          + r.stderr.strip().splitlines()[-1])

            if sig_ok and args.roots and chain_ok:
                print(f"    chain:      VERIFIED against {args.roots}")

            sig_ok_all &= bool(sig_ok)
            if args.roots:
                chain_ok_all &= bool(chain_ok)
            if not sig_ok:
                failures.append(f"signature#{s['i'] + 1}")

        # ---- 4. payload integrity ----------------------------------------
        if args.deep:
            n = bad = 0
            for fe in toc.iter("file"):
                d = fe.find("data")
                if d is None or d.find("archived-checksum") is None:
                    continue
                n += 1
                f.seek(heap_base + int(d.findtext("offset")))
                blob = read_exact(f, int(d.findtext("length")),
                                  f"file data for {fe.findtext('name')}")
                ac = d.find("archived-checksum")
                if hashlib.new(ac.get("style", "sha1"), blob).hexdigest() \
                        != ac.text.strip():
                    bad += 1
                    print(f"  TAMPERED:   {fe.findtext('name')}")
            print(f"  payload:    {n} files checked, {bad} checksum mismatch(es)")
            if bad:
                failures.append("payload")

    # ---- verdict ----------------------------------------------------------
    print()
    if not sig_els:
        print("Status: UNSIGNED")
    elif sig_ok_all and args.roots and chain_ok_all:
        print("Status: SIGNED, all signatures valid, chain of trust VERIFIED")
        print("        (pkgutil equivalent: 'signed by a certificate trusted"
              " by macOS')")
    elif sig_ok_all and not args.roots:
        print("Status: SIGNED, signature valid — pass --roots to verify the"
              " chain of trust")
    elif sig_ok_all:
        print("Status: SIGNED, signature valid, but chain NOT verified")
    else:
        print("Status: SIGNATURE INVALID or package TAMPERED")
    if failures:
        print(f"Failed checks: {', '.join(failures)}")
        sys.exit(1)
    if sig_els and not (args.roots and chain_ok_all):
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
