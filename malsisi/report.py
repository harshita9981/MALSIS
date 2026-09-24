"""Render the analysis result as HTML, plain text, JSON or PDF."""
from __future__ import annotations

import datetime as dt
import html
import json

from .utils import defang

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
VERDICT_TONE = {
    "Malicious": "bad", "Likely malicious": "bad", "Suspicious": "warn",
    "Low risk": "mild", "No indicators": "good",
}

CSS = """
:root{
  --paper:#ffffff; --sunk:#f4f6f8; --ink:#14181d; --muted:#5c6670; --rule:#dde2e7;
  --high:#b32318; --medium:#b4690e; --low:#5b6670; --info:#2f5d8c;
  --bad:#8c1d14; --warn:#a35c06; --mild:#4a5560; --good:#1f6b3a;
}
@media (prefers-color-scheme: dark){
  :root{ --paper:#14181c; --sunk:#1b2026; --ink:#e6eaee; --muted:#97a2ad; --rule:#2b333b;
         --high:#f08072; --medium:#e2a33f; --low:#9aa5b0; --info:#7db3e0;
         --bad:#e05a4a; --warn:#d1902c; --mild:#7d8893; --good:#54b47a; }
}
*{box-sizing:border-box}
body{margin:0;padding:0 1.5rem 5rem;background:var(--paper);color:var(--ink);
  font-family:"Inter",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  font-size:15px;line-height:1.55;-webkit-font-smoothing:antialiased}
main{max-width:64rem;margin:0 auto}
code,.mono,td.mono,pre{font-family:ui-monospace,"SFMono-Regular",Menlo,Consolas,monospace;font-size:.86em}
pre{background:var(--sunk);padding:.9rem 1rem;border-radius:3px;overflow-x:auto;white-space:pre-wrap;word-break:break-word}
h1{font-size:1.5rem;font-weight:600;margin:2.2rem 0 .2rem;letter-spacing:-.01em;word-break:break-all}
h2{font-size:1.05rem;font-weight:600;margin:2.6rem 0 .7rem;padding-bottom:.35rem;border-bottom:1px solid var(--rule)}
h3{font-size:.95rem;font-weight:600;margin:1.4rem 0 .4rem;color:var(--muted)}
p{margin:.4rem 0}
.sub{color:var(--muted);font-size:.9rem;margin-bottom:1.4rem}
.verdict{display:flex;flex-wrap:wrap;align-items:baseline;gap:1rem;
  padding:1.1rem 1.3rem;border-radius:4px;color:#fff;margin:1rem 0 1.6rem}
.verdict.bad{background:var(--bad)} .verdict.warn{background:var(--warn)}
.verdict.mild{background:var(--mild)} .verdict.good{background:var(--good)}
.verdict .name{font-size:1.5rem;font-weight:650;letter-spacing:-.01em}
.verdict .score{font-size:.92rem;opacity:.88}
dl.facts{display:grid;grid-template-columns:11rem 1fr;gap:.35rem 1.2rem;margin:.8rem 0}
dl.facts dt{color:var(--muted);font-size:.87rem}
dl.facts dd{margin:0;word-break:break-all}
table{width:100%;border-collapse:collapse;margin:.6rem 0;font-size:.9rem}
th{text-align:left;font-weight:600;color:var(--muted);font-size:.82rem;
  border-bottom:1px solid var(--rule);padding:.35rem .6rem .35rem 0}
td{padding:.4rem .6rem .4rem 0;border-bottom:1px solid var(--rule);vertical-align:top;word-break:break-word}
tr:last-child td{border-bottom:0}
.findings td:first-child{border-left:3px solid var(--rule);padding-left:.7rem;white-space:nowrap;font-size:.8rem}
.findings tr.high td:first-child{border-left-color:var(--high);color:var(--high)}
.findings tr.medium td:first-child{border-left-color:var(--medium);color:var(--medium)}
.findings tr.low td:first-child{border-left-color:var(--low);color:var(--low)}
.findings tr.info td:first-child{border-left-color:var(--info);color:var(--info)}
details{margin:.5rem 0;border-top:1px solid var(--rule)}
summary{cursor:pointer;padding:.5rem 0;color:var(--muted);font-size:.9rem}
summary:hover{color:var(--ink)}
summary::marker{color:var(--muted)}
.tag{display:inline-block;background:var(--sunk);border-radius:3px;padding:.08rem .4rem;
  margin:.12rem .25rem .12rem 0;font-size:.82rem}
.spark{display:block;width:100%;height:38px;margin:.5rem 0}
.note{color:var(--muted);font-size:.88rem;font-style:normal}
footer{margin-top:3rem;padding-top:.8rem;border-top:1px solid var(--rule);color:var(--muted);font-size:.82rem}
@media print{
  body{padding:0;font-size:11pt}
  .verdict{-webkit-print-color-adjust:exact;print-color-adjust:exact}
  details{display:block} details>summary{display:none} details>*{display:block!important}
  h2{break-after:avoid} table{break-inside:auto} tr{break-inside:avoid}
}
@media (max-width:620px){ dl.facts{grid-template-columns:1fr;gap:0 0} dl.facts dd{margin-bottom:.5rem} }
"""


def e(value):
    return html.escape(str(value if value is not None else ""), quote=True)


def _table(headers, rows, cls=""):
    if not rows:
        return ""
    head = "".join(f"<th>{e(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows)
    return f'<table class="{cls}"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>'


def _details(title, inner, open_=False):
    if not inner:
        return ""
    return f"<details{' open' if open_ else ''}><summary>{e(title)}</summary>{inner}</details>"


def _sparkline(values):
    if not values:
        return ""
    width, height = 900, 38
    step = width / max(len(values), 1)
    points = " ".join(f"{i * step:.1f},{height - (v / 8.0) * height:.1f}" for i, v in enumerate(values))
    return (f'<svg class="spark" viewBox="0 0 {width} {height}" preserveAspectRatio="none" '
            f'role="img" aria-label="Entropy across the file">'
            f'<polyline points="{points}" fill="none" stroke="currentColor" stroke-width="1.5" opacity=".55"/>'
            f'<line x1="0" y1="{height - (7.2 / 8.0) * height:.1f}" x2="{width}" '
            f'y2="{height - (7.2 / 8.0) * height:.1f}" stroke="currentColor" stroke-dasharray="4 4" opacity=".25"/></svg>')


# --------------------------------------------------------------------------- HTML


def to_html(result):
    static = result["static"]
    dyn = result.get("dynamic")
    ov = static["overview"]
    verdict = result.get("verdict", static["verdict"])
    score = result.get("score", static["score"])
    tone = VERDICT_TONE.get(verdict, "mild")
    parts = []

    parts.append(f'<h1>{e(ov["file_name"])}</h1>')
    parts.append(f'<p class="sub">{e(ov["type"]["label"])} &middot; {e(ov["file_size_h"])} &middot; '
                 f'analysed {e(result["generated"])}</p>')
    parts.append(f'<div class="verdict {tone}"><span class="name">{e(verdict)}</span>'
                 f'<span class="score">Risk score {e(score)} of 100 &middot; '
                 f'{len([f for f in result["findings"] if f["severity"] in ("high", "medium")])} notable findings</span></div>')

    # identification
    h = ov["hashes"]
    facts = [
        ("SHA-256", f'<span class="mono">{e(h["sha256"])}</span>'),
        ("SHA-1", f'<span class="mono">{e(h["sha1"])}</span>'),
        ("MD5", f'<span class="mono">{e(h["md5"])}</span>'),
    ]
    for extra, label in (("ssdeep", "ssdeep"), ("tlsh", "TLSH")):
        if h.get(extra):
            facts.append((label, f'<span class="mono">{e(h[extra])}</span>'))
    if static.get("pe", {}).get("imphash"):
        facts.append(("imphash", f'<span class="mono">{e(static["pe"]["imphash"])}</span>'))
    facts += [
        ("Size", e(f'{ov["file_size"]:,} bytes ({ov["file_size_h"]})')),
        ("File type", e(ov["type"]["label"])),
        ("Magic bytes", f'<span class="mono">{e(ov["type"]["magic"])}</span>'),
    ]
    if ov["type"].get("libmagic"):
        facts.append(("libmagic", e(ov["type"]["libmagic"])))
    facts.append(("Entropy", e(ov["entropy"]) + ' <span class="note">(8.0 = fully random)</span>'))
    parts.append("<h2>Identification</h2>")
    parts.append("<dl class=\"facts\">" + "".join(f"<dt>{e(k)}</dt><dd>{v}</dd>" for k, v in facts) + "</dl>")
    parts.append(_sparkline(static.get("entropy_map")))

    # findings
    findings = sorted(result["findings"], key=lambda f: SEV_ORDER.get(f["severity"], 9))
    if findings:
        rows = [(e(f["severity"]), f'<strong>{e(f["title"])}</strong>'
                 + (f'<br><span class="note">{e(f["detail"])}</span>' if f.get("detail") else ""),
                 e(f.get("source", "static"))) for f in findings]
        parts.append("<h2>Findings</h2>")
        parts.append(_table(["Severity", "Finding", "Source"], rows, cls="findings"))

    # IOCs
    iocs = static.get("iocs") or {}
    if iocs:
        parts.append("<h2>Indicators extracted from the file</h2>")
        parts.append('<p class="note">Network indicators are defanged. These are strings found in the file, '
                     'not proof of contact.</p>')
        for name, values in iocs.items():
            label = {"url": "URLs", "ipv4": "IP addresses", "domain": "Domains", "email": "Email addresses",
                     "win_path": "Windows paths", "registry": "Registry keys", "bitcoin": "Bitcoin addresses",
                     "mutex": "Mutex names", "onion": "Onion addresses"}.get(name, name)
            shown = values[:60]
            body = "".join(
                f'<span class="tag mono">{e(defang(v) if name in ("url", "domain", "ipv4", "email", "onion") else v)}</span>'
                for v in shown)
            if len(values) > len(shown):
                body += f'<span class="note"> and {len(values) - len(shown)} more</span>'
            parts.append(_details(f"{label} ({len(values)})", f"<p>{body}</p>", open_=name in ("url", "ipv4", "domain")))

    # PE
    pe = static.get("pe")
    if pe and not pe.get("skipped"):
        parts.append("<h2>Portable executable</h2>")
        pe_facts = [("Machine", e(pe.get("machine"))), ("Subsystem", e(pe.get("subsystem"))),
                    ("Compiled", e(pe.get("compiled"))), ("Entry point", e(pe.get("entry_point"))),
                    ("Type", e("DLL" if pe.get("is_dll") else "Driver" if pe.get("is_driver") else "Executable")
                     + (" (.NET)" if pe.get("dotnet") else "")),
                    ("Signed", "Yes" if pe.get("signed") else "No"),
                    ("Imported functions", e(pe.get("import_count", 0)))]
        if pe.get("pdb_path"):
            pe_facts.append(("PDB path", f'<span class="mono">{e(pe["pdb_path"])}</span>'))
        if pe.get("overlay"):
            pe_facts.append(("Overlay", e(f'{pe["overlay"]["size"]:,} bytes, entropy {pe["overlay"]["entropy"]}')))
        parts.append("<dl class=\"facts\">" + "".join(f"<dt>{e(k)}</dt><dd>{v}</dd>" for k, v in pe_facts) + "</dl>")

        if pe.get("suspicious_imports"):
            parts.append("<h3>Notable imports by capability</h3>")
            rows = [(e(cat), " ".join(f'<span class="tag mono">{e(a)}</span>' for a in apis)) for cat, apis in pe["suspicious_imports"].items()]
            parts.append(_table(["Capability", "Functions"], rows))
        if pe.get("sections"):
            rows = [(f'<span class="mono">{e(s["name"])}</span>', f'{s["virtual_size"]:,}', f'{s["raw_size"]:,}',
                     e(s["entropy"]), ("X" if s["executable"] else "") + ("W" if s["writable"] else "") or "&ndash;")
                    for s in pe["sections"]]
            parts.append(_details(f'Sections ({len(pe["sections"])})',
                                  _table(["Name", "Virtual size", "Raw size", "Entropy", "Flags"], rows), open_=True))
        if pe.get("imports"):
            inner = "".join(f'<h3>{e(dll)}</h3><p>' + " ".join(f'<span class="tag mono">{e(fn)}</span>' for fn in funcs) + "</p>"
                            for dll, funcs in pe["imports"].items())
            parts.append(_details(f'Full import table ({len(pe["imports"])} DLLs)', inner))
        if pe.get("exports"):
            parts.append(_details(f'Exports ({len(pe["exports"])})',
                                  "<p>" + " ".join(f'<span class="tag mono">{e(x)}</span>' for x in pe["exports"]) + "</p>"))
        if pe.get("resources"):
            rows = [(e(r["type"]), f'{r["size"]:,}', e(r["entropy"])) for r in pe["resources"]]
            parts.append(_details(f'Resources ({len(pe["resources"])})', _table(["Type", "Size", "Entropy"], rows)))
    elif pe and pe.get("skipped"):
        parts.append(f'<h2>Portable executable</h2><p class="note">{e(pe["skipped"])}</p>')

    # PDF
    pdf = static.get("pdf")
    if pdf:
        parts.append("<h2>PDF structure</h2>")
        parts.append("<dl class=\"facts\">"
                     f'<dt>Version</dt><dd>{e(pdf.get("version"))}</dd>'
                     f'<dt>Objects</dt><dd>{e(pdf.get("objects"))}</dd>'
                     f'<dt>Streams</dt><dd>{e(pdf.get("streams"))} '
                     f'({e(pdf.get("decompressed_streams"))} decompressed)</dd></dl>')
        if pdf.get("keywords"):
            rows = [(f'<span class="mono">{e(k)}</span>', e(v)) for k, v in pdf["keywords"].items()]
            parts.append(_table(["Keyword", "Count"], rows))
        for i, js in enumerate(pdf.get("javascript", []), 1):
            parts.append(_details(f"Embedded JavaScript #{i}", f"<pre>{e(js)}</pre>", open_=i == 1))

    # Office
    office = static.get("office")
    if office:
        parts.append("<h2>Document content</h2>")
        if office.get("skipped"):
            parts.append(f'<p class="note">{e(office["skipped"])}</p>')
        if office.get("autoexec"):
            parts.append("<p>Auto-run triggers: " + " ".join(f'<span class="tag mono">{e(a)}</span>' for a in office["autoexec"]) + "</p>")
        if office.get("suspicious_keywords"):
            parts.append("<p>Suspicious keywords: " + " ".join(f'<span class="tag mono">{e(k)}</span>' for k in office["suspicious_keywords"]) + "</p>")
        if office.get("external_targets"):
            parts.append("<p>External targets: " + " ".join(f'<span class="tag mono">{e(defang(t))}</span>' for t in office["external_targets"]) + "</p>")
        for macro in office.get("macros", []):
            parts.append(_details(f'Macro module: {macro["name"]} ({macro["lines"]} lines)', f'<pre>{e(macro["code"])}</pre>'))
        if office.get("olevba_findings"):
            rows = [(e(f["type"]), f'<span class="mono">{e(f["keyword"])}</span>', e(f["description"])) for f in office["olevba_findings"]]
            parts.append(_details("olevba analysis", _table(["Type", "Keyword", "Description"], rows)))
        if office.get("entries"):
            parts.append(_details(f'Container entries ({len(office["entries"])})',
                                  "<p>" + " ".join(f'<span class="tag mono">{e(n)}</span>' for n in office["entries"]) + "</p>"))

    # Archive
    arch = static.get("archive")
    if arch and arch.get("entries"):
        rows = [(f'<span class="mono">{e(i["name"])}</span>', f'{i["size"]:,}', "yes" if i["encrypted"] else "no")
                for i in arch["entries"]]
        parts.append("<h2>Archive contents</h2>")
        parts.append(_table(["Name", "Size", "Encrypted"], rows))

    # YARA
    yara_res = static.get("yara") or {}
    parts.append("<h2>YARA</h2>")
    if yara_res.get("skipped") or yara_res.get("error"):
        parts.append(f'<p class="note">{e(yara_res.get("skipped") or yara_res.get("error"))}</p>')
    elif yara_res.get("matches"):
        rows = [(f'<span class="mono">{e(m["rule"])}</span>', e(m["meta"].get("description", "")),
                 " ".join(f'<span class="tag mono">{e(s)}</span>' for s in m["strings"]))
                for m in yara_res["matches"]]
        parts.append(_table(["Rule", "Description", "Matched strings"], rows))
    else:
        parts.append(f'<p class="note">No rules matched ({len(yara_res.get("rule_files", []))} rule files loaded).</p>')

    # Dynamic
    parts.append("<h2>Dynamic analysis</h2>")
    if not dyn:
        parts.append(f'<p class="note">{e(result.get("dynamic_note", "Not run."))}</p>')
    elif dyn.get("error"):
        parts.append(f'<p class="note">Sandbox run failed: {e(dyn["error"])}</p>')
    else:
        dfacts = [("Backend", e(dyn.get("backend"))), ("Task", f'<span class="mono">{e(dyn.get("task_id"))}</span>')]
        if dyn.get("score") is not None:
            dfacts.append(("Sandbox score", e(dyn.get("detections") or dyn.get("score"))))
        if dyn.get("family"):
            dfacts.append(("Family", e(", ".join(dyn["family"][:10]))))
        if dyn.get("url"):
            dfacts.append(("Report", f'<a href="{e(dyn["url"])}">{e(dyn["url"])}</a>'))
        parts.append("<dl class=\"facts\">" + "".join(f"<dt>{e(k)}</dt><dd>{v}</dd>" for k, v in dfacts) + "</dl>")
        if dyn.get("note"):
            parts.append(f'<p class="note">{e(dyn["note"])}</p>')
        if dyn.get("mitre"):
            parts.append("<p>ATT&amp;CK: " + " ".join(f'<span class="tag mono">{e(t)}</span>' for t in dyn["mitre"]) + "</p>")
        if dyn.get("signatures"):
            rows = [(e(s.get("name")), e(s.get("description"))) for s in dyn["signatures"]]
            parts.append(_details(f'Sandbox signatures ({len(rows)})', _table(["Signature", "Description"], rows), open_=True))
        if dyn.get("processes"):
            rows = [(e(p.get("pid")), e(p.get("name")), f'<span class="mono">{e(p.get("cmdline"))}</span>') for p in dyn["processes"]]
            parts.append(_details(f'Processes ({len(rows)})', _table(["PID", "Image", "Command line"], rows)))
        net = dyn.get("network") or {}
        for key, label in (("dns", "DNS lookups"), ("hosts", "Contacted hosts"), ("http", "HTTP requests")):
            values = [v for v in (net.get(key) or []) if v]
            if values:
                parts.append(_details(f"{label} ({len(values)})",
                                      "<p>" + " ".join(f'<span class="tag mono">{e(defang(str(v)))}</span>' for v in values) + "</p>",
                                      open_=key == "dns"))
        for key, label in (("files", "Files written"), ("registry", "Registry keys set"), ("mutexes", "Mutexes")):
            values = [v for v in (dyn.get(key) or []) if v]
            if values:
                parts.append(_details(f"{label} ({len(values)})",
                                      "<p>" + " ".join(f'<span class="tag mono">{e(v)}</span>' for v in values) + "</p>"))
        if dyn.get("dropped"):
            rows = [(e(d.get("name")), f'<span class="mono">{e(d.get("sha256"))}</span>', e(d.get("type"))) for d in dyn["dropped"]]
            parts.append(_details(f'Dropped files ({len(rows)})', _table(["Name", "SHA-256", "Type"], rows)))

    # strings
    strings = static.get("strings") or []
    if strings:
        shown = strings[:1500]
        parts.append("<h2>Strings</h2>")
        parts.append(_details(f"Printable strings ({len(strings)} unique, showing {len(shown)})",
                              f'<pre>{e(chr(10).join(shown))}</pre>'))

    parts.append(f'<footer>malysis {e(result["tool_version"])} &middot; static analysis only unless a sandbox '
                 f'backend is named &middot; generated {e(result["generated"])}</footer>')

    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>{e(ov['file_name'])} — analysis report</title><style>{CSS}</style></head>"
        f"<body><main>{''.join(parts)}</main></body></html>"
    )


# --------------------------------------------------------------------------- text


def to_text(result):
    static = result["static"]
    ov = static["overview"]
    lines = []
    add = lines.append
    add("=" * 72)
    add(f'FILE ANALYSIS REPORT  {ov["file_name"]}')
    add("=" * 72)
    add(f'Verdict      : {result.get("verdict", static["verdict"])}  (score {result.get("score", static["score"])}/100)')
    add(f'Type         : {ov["type"]["label"]}')
    add(f'Size         : {ov["file_size"]:,} bytes   Entropy: {ov["entropy"]}')
    for key in ("sha256", "sha1", "md5", "ssdeep", "tlsh"):
        if ov["hashes"].get(key):
            add(f'{key.upper():<13}: {ov["hashes"][key]}')
    if static.get("pe", {}).get("imphash"):
        add(f'IMPHASH      : {static["pe"]["imphash"]}')
    add(f'Generated    : {result["generated"]}')

    add("")
    add("-- FINDINGS " + "-" * 60)
    for f in sorted(result["findings"], key=lambda x: SEV_ORDER.get(x["severity"], 9)):
        add(f'[{f["severity"].upper():<6}] {f["title"]}')
        if f.get("detail"):
            add(f'          {f["detail"]}')
    if not result["findings"]:
        add("none")

    iocs = static.get("iocs") or {}
    if iocs:
        add("")
        add("-- INDICATORS " + "-" * 58)
        for name, values in iocs.items():
            add(f"{name}:")
            for v in values[:80]:
                add(f"  {defang(v) if name in ('url', 'domain', 'ipv4', 'email', 'onion') else v}")

    dyn = result.get("dynamic")
    add("")
    add("-- DYNAMIC " + "-" * 61)
    if not dyn:
        add(result.get("dynamic_note", "not run"))
    elif dyn.get("error"):
        add(f'failed: {dyn["error"]}')
    else:
        add(f'backend: {dyn.get("backend")}  task: {dyn.get("task_id")}  score: {dyn.get("detections") or dyn.get("score")}')
        if dyn.get("url"):
            add(f'report : {dyn["url"]}')
        for sig in (dyn.get("signatures") or [])[:40]:
            add(f'  sig: {sig.get("name")}')
        net = dyn.get("network") or {}
        for key in ("dns", "hosts", "http"):
            for v in (net.get(key) or [])[:40]:
                if v:
                    add(f'  {key}: {defang(str(v))}')
    return "\n".join(lines) + "\n"


def to_json(result):
    return json.dumps(result, indent=2, default=str)


def to_pdf(result, out_path):
    html_doc = to_html(result)
    try:
        from weasyprint import HTML  # type: ignore
    except ImportError:
        raise RuntimeError(
            "PDF output needs weasyprint (pip install weasyprint). "
            "Alternatively write HTML and print it to PDF from a browser."
        )
    HTML(string=html_doc).write_pdf(out_path)


def render(result, fmt, out_path):
    if fmt == "pdf":
        to_pdf(result, out_path)
        return
    body = {"html": to_html, "txt": to_text, "text": to_text, "json": to_json}[fmt](result)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(body)


def stamp():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
