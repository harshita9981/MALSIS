"""One entry point used by both the CLI and the GUI."""
from __future__ import annotations

import os
import sys

from . import __version__
from .identify import identify
from .report import stamp
from .static import SEV_WEIGHT, run_static, verdict_for

def _default_rules():
    here = os.path.dirname(os.path.abspath(__file__))
    bundled = os.path.join(getattr(sys, "_MEIPASS", ""), "malysis", "rules")
    if getattr(sys, "frozen", False) and os.path.isdir(bundled):
        return bundled
    return os.path.join(here, "rules")


DEFAULT_RULES = _default_rules()

NOT_RUN = "Not run. Choose a sandbox backend to detonate the sample."


def analyse(path, *, rules=DEFAULT_RULES, max_strings=4000, min_string_len=6,
            dynamic=None, sandbox_url=None, api_key=None, timeout=900, poll=15,
            insecure=False, vt_upload=False, progress=None):
    """Run static analysis, then optionally a sandbox, and return the result dict."""
    def say(message):
        if progress:
            progress(message)

    path = os.path.abspath(path)
    say(f"Identifying {os.path.basename(path)}")
    ident = identify(path)
    say(f"Type: {ident['label']}")

    say("Running static analysis")
    static = run_static(path, ident, {
        "rules": rules, "max_strings": max_strings, "min_string_len": min_string_len,
    })
    say(f"Static analysis found {len(static['findings'])} indicators")

    result = {
        "tool_version": __version__,
        "generated": stamp(),
        "sample_path": path,
        "static": static,
        "findings": list(static["findings"]),
        "dynamic": None,
        "dynamic_note": NOT_RUN,
    }

    if dynamic and dynamic.lower() != "none":
        from .dynamic import build_backend, findings_from_dynamic

        try:
            backend = build_backend(dynamic.lower(), url=sandbox_url, api_key=api_key,
                                    timeout=timeout, poll=poll, insecure=insecure,
                                    vt_upload=vt_upload)
            say(f"Submitting to {backend.name}. This can take several minutes.")
            dyn = backend.run(path)
            result["dynamic"] = dyn
            result["findings"].extend(findings_from_dynamic(dyn))
            say("Sandbox report retrieved")
        except Exception as exc:
            result["dynamic"] = {"backend": dynamic, "error": str(exc)}
            say(f"Dynamic analysis failed: {exc}")

    result["score"] = min(100, sum(SEV_WEIGHT.get(f["severity"], 0) for f in result["findings"]))
    result["verdict"] = verdict_for(result["score"])
    say(f'Verdict: {result["verdict"]} ({result["score"]}/100)')
    return result
