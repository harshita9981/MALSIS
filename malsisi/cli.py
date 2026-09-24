"""Command line entry point."""
from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .engine import DEFAULT_RULES, analyse
from .report import render

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def build_parser():
    p = argparse.ArgumentParser(
        prog="malysis",
        description="Triage a file: static analysis, optional sandbox detonation, one report.",
    )
    p.add_argument("sample", help="path to the file to analyse")
    p.add_argument("-o", "--output", help="report path (default: <sample>.report.<ext>)")
    p.add_argument("-f", "--format", default="html", choices=["html", "txt", "json", "pdf"],
                   help="report format (default: html)")
    p.add_argument("--rules", default=DEFAULT_RULES, help="YARA rules directory")
    p.add_argument("--max-strings", type=int, default=4000, help="cap on unique strings kept")
    p.add_argument("--min-string-len", type=int, default=6, help="minimum string length")

    d = p.add_argument_group("dynamic analysis")
    d.add_argument("--dynamic", default="none", help="sandbox backend: cape, triage, vt, or none")
    d.add_argument("--sandbox-url", help="base URL of the sandbox (env: MALYSIS_SANDBOX_URL)")
    d.add_argument("--api-key", help="API key or token (env: MALYSIS_API_KEY)")
    d.add_argument("--timeout", type=int, default=900, help="seconds to wait for the sandbox")
    d.add_argument("--poll", type=int, default=15, help="seconds between status checks")
    d.add_argument("--insecure", action="store_true", help="skip TLS verification (self-signed CAPE)")
    d.add_argument("--vt-upload", action="store_true", help="allow uploading the sample to VirusTotal if unknown")

    p.add_argument("--gui", action="store_true", help="open the desktop interface instead")
    p.add_argument("-q", "--quiet", action="store_true", help="only print the output path")
    p.add_argument("--version", action="version", version=f"malysis {__version__}")
    return p


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--gui" in argv or not argv:
        from .gui import launch
        return launch()

    args = build_parser().parse_args(argv)
    path = os.path.abspath(args.sample)
    if not os.path.isfile(path):
        print(f"not a file: {path}", file=sys.stderr)
        return 2

    result = analyse(
        path, rules=args.rules, max_strings=args.max_strings, min_string_len=args.min_string_len,
        dynamic=args.dynamic, sandbox_url=args.sandbox_url, api_key=args.api_key,
        timeout=args.timeout, poll=args.poll, insecure=args.insecure, vt_upload=args.vt_upload,
        progress=None if args.quiet else lambda m: print(f"[*] {m}", file=sys.stderr),
    )

    out = args.output or f"{path}.report.{args.format}"
    render(result, args.format, out)

    if args.quiet:
        print(out)
    else:
        print(f"\n  {result['verdict']}  (score {result['score']}/100)")
        for f in sorted(result["findings"], key=lambda x: SEV_ORDER.get(x["severity"], 9))[:8]:
            print(f"  [{f['severity']:<6}] {f['title']}")
        if len(result["findings"]) > 8:
            print(f"  ... {len(result['findings']) - 8} more in the report")
        print(f"\n  report: {out}")
    return 0
