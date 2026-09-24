"""Static analysis modules. Nothing here executes the sample."""
from __future__ import annotations

import datetime as dt
import os
import re
import zipfile

from .utils import (defang, entropy, entropy_map, extract_iocs, extract_strings,
                    hash_file, human_size, try_inflate)

SEV_WEIGHT = {"info": 0, "low": 6, "medium": 16, "high": 30}

SUSPICIOUS_APIS = {
    "process injection": [
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx",
        "QueueUserAPC", "NtUnmapViewOfSection", "SetThreadContext", "RtlCreateUserThread",
        "NtMapViewOfSection", "OpenProcess",
    ],
    "dynamic api resolution": ["LoadLibraryA", "LoadLibraryW", "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress"],
    "memory permissions": ["VirtualProtect", "VirtualProtectEx", "VirtualAlloc", "NtProtectVirtualMemory"],
    "anti-analysis": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "OutputDebugString", "GetTickCount", "QueryPerformanceCounter", "NtSetInformationThread",
        "BlockInput", "FindWindowA",
    ],
    "persistence": [
        "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
        "CreateServiceA", "CreateServiceW", "OpenSCManagerA", "StartServiceA", "SetWindowsHookExA",
    ],
    "credential / keylogging": [
        "GetAsyncKeyState", "GetKeyboardState", "SetWindowsHookExW", "CredEnumerateA",
        "CryptUnprotectData", "LsaOpenPolicy", "SamIConnect",
    ],
    "network": [
        "InternetOpenA", "InternetOpenUrlA", "InternetReadFile", "HttpSendRequestA",
        "URLDownloadToFileA", "URLDownloadToFileW", "WinHttpOpen", "WSAStartup", "connect",
        "send", "recv", "socket", "gethostbyname", "DnsQuery_A",
    ],
    "execution": ["WinExec", "ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW", "system"],
    "crypto / ransom": [
        "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContextA", "BCryptEncrypt",
        "FindFirstFileA", "FindNextFileA", "DeleteFileA", "MoveFileExA", "SetFileAttributesA",
    ],
    "privilege / token": ["AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValueA", "ImpersonateLoggedOnUser"],
    "discovery": ["CreateToolhelp32Snapshot", "Process32First", "Process32Next", "EnumProcesses", "GetComputerNameA", "GetUserNameA"],
}

PACKER_SECTIONS = {
    "UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX", ".aspack": "ASPack", ".adata": "ASPack",
    ".nsp0": "NsPack", ".petite": "Petite", "FSG!": "FSG", ".MPRESS1": "MPRESS",
    ".themida": "Themida", ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".enigma1": "Enigma",
    ".boom": "Boomerang", "pebundle": "PEBundle", ".taz": "PESpin",
}

PDF_KEYWORDS = [
    ("/JavaScript", "high", "JavaScript object present"),
    ("/JS", "high", "JavaScript action present"),
    ("/OpenAction", "medium", "Action fires on document open"),
    ("/AA", "medium", "Additional (automatic) action defined"),
    ("/Launch", "high", "Launch action can start an external program"),
    ("/EmbeddedFile", "high", "File embedded inside the PDF"),
    ("/GoToE", "medium", "Embedded go-to action"),
    ("/SubmitForm", "medium", "Form submits data to a remote endpoint"),
    ("/URI", "low", "External URI reference"),
    ("/RichMedia", "high", "Flash/rich media object"),
    ("/XFA", "medium", "XFA form (historically abused)"),
    ("/JBIG2Decode", "medium", "JBIG2 decoder (historic exploit vector)"),
    ("/ObjStm", "low", "Object streams present (can hide objects)"),
    ("/Encrypt", "low", "Document is encrypted"),
]

VBA_AUTOEXEC = [
    "AutoOpen", "Auto_Open", "AutoExec", "AutoClose", "Document_Open", "DocumentOpen",
    "Workbook_Open", "Auto_Close", "Document_Close", "NewDocument",
]
VBA_SUSPICIOUS = [
    "Shell", "WScript.Shell", "CreateObject", "GetObject", "powershell", "cmd.exe",
    "MSXML2.XMLHTTP", "WinHttp", "URLDownloadToFile", "ADODB.Stream", "SaveToFile",
    "Environ", "Chr(", "StrReverse", "Xor", "ExecuteExcel4Macro", "Declare PtrSafe",
    "VirtualAlloc", "CallWindowProc", "Base64Decode", "schtasks", "regsvr32", "rundll32", "mshta",
]


class Report(dict):
    """Plain dict with a findings helper."""

    def add(self, severity, title, detail="", source="static"):
        self.setdefault("findings", []).append(
            {"severity": severity, "title": title, "detail": detail, "source": source}
        )


# --------------------------------------------------------------------------- PE


def analyse_pe(path, data, rep):
    try:
        import pefile
    except ImportError:
        return {"skipped": "pefile not installed (pip install pefile)"}

    try:
        pe = pefile.PE(str(path), fast_load=False)
    except Exception as exc:
        rep.add("medium", "PE header is malformed", str(exc))
        return {"error": str(exc)}

    out = {}
    out["machine"] = pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
    out["subsystem"] = pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, "?")
    out["is_dll"] = bool(pe.is_dll())
    out["is_driver"] = bool(pe.is_driver())
    out["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    out["image_base"] = hex(pe.OPTIONAL_HEADER.ImageBase)

    ts = pe.FILE_HEADER.TimeDateStamp
    try:
        compiled = dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        compiled = f"invalid ({ts})"
    out["compiled"] = compiled
    now = dt.datetime.now(dt.timezone.utc).timestamp()
    if ts == 0:
        rep.add("low", "Compile timestamp is zeroed", "Often a sign of timestamp tampering.")
    elif ts > now + 86400:
        rep.add("medium", "Compile timestamp is in the future", compiled)
    elif ts < 946684800:  # 2000-01-01
        rep.add("low", "Compile timestamp predates 2000", compiled)

    try:
        out["imphash"] = pe.get_imphash()
    except Exception:
        pass

    # sections
    sections = []
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_section = None
    for idx, sec in enumerate(pe.sections):
        name = sec.Name.rstrip(b"\x00").decode("latin-1", "ignore")
        body = sec.get_data()
        ent = round(entropy(body), 3)
        item = {
            "name": name,
            "virtual_size": sec.Misc_VirtualSize,
            "raw_size": sec.SizeOfRawData,
            "entropy": ent,
            "characteristics": hex(sec.Characteristics),
            "executable": bool(sec.Characteristics & 0x20000000),
            "writable": bool(sec.Characteristics & 0x80000000),
        }
        sections.append(item)
        if sec.contains_rva(ep):
            ep_section = (idx, name)
        if ent > 7.2 and sec.SizeOfRawData > 4096:
            rep.add("medium", f"High entropy section: {name}", f"entropy {ent} — packed, compressed or encrypted.")
        if item["executable"] and item["writable"]:
            rep.add("medium", f"Section {name} is both writable and executable", "Common in packers and self-modifying code.")
        if sec.SizeOfRawData == 0 and sec.Misc_VirtualSize > 0x1000:
            rep.add("medium", f"Section {name} has no raw data but a large virtual size", "Typical unpacking stub layout.")
        packer = PACKER_SECTIONS.get(name)
        if packer:
            rep.add("medium", f"Packer section name: {name}", f"Matches {packer}.")
    out["sections"] = sections
    if ep_section and ep_section[0] == len(pe.sections) - 1 and len(pe.sections) > 1:
        rep.add("medium", "Entry point sits in the last section", f"Section {ep_section[1]} — common after packing.")
    if ep_section is None:
        rep.add("high", "Entry point is outside every mapped section", out["entry_point"])

    # imports
    imports = {}
    flat = []
    pe.parse_data_directories()
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = entry.dll.decode("latin-1", "ignore") if entry.dll else "?"
        funcs = [imp.name.decode("latin-1", "ignore") for imp in entry.imports if imp.name]
        imports[dll] = sorted(funcs)
        flat.extend(funcs)
    out["imports"] = imports
    out["import_count"] = len(flat)

    lowered = {f.lower(): f for f in flat}
    categories = {}
    for cat, apis in SUSPICIOUS_APIS.items():
        hit = sorted({lowered[a.lower()] for a in apis if a.lower() in lowered})
        if hit:
            categories[cat] = hit
    out["suspicious_imports"] = categories
    for cat, hit in categories.items():
        sev = "high" if cat in ("process injection", "credential / keylogging") else "medium"
        rep.add(sev, f"Imports associated with {cat}", ", ".join(hit[:12]))

    if flat and len(flat) < 8:
        rep.add("medium", "Very small import table", f"{len(flat)} imported functions — typical of packed or API-hashing code.")
    if not imports and not out.get("is_driver"):
        rep.add("high", "No import table at all", "The binary resolves its APIs at runtime.")

    # exports
    exports = []
    for exp in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []) or []:
        if exp.name:
            exports.append(exp.name.decode("latin-1", "ignore"))
    out["exports"] = sorted(exports)[:200]

    # resources
    resources = []
    for rtype in getattr(getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None), "entries", []) or []:
        type_name = str(rtype.name) if rtype.name else pefile.RESOURCE_TYPE.get(rtype.struct.Id, str(rtype.struct.Id))
        for rid in getattr(rtype, "directory", {}).entries if hasattr(rtype, "directory") else []:
            for lang in getattr(rid, "directory", {}).entries if hasattr(rid, "directory") else []:
                try:
                    blob = pe.get_data(lang.data.struct.OffsetToData, lang.data.struct.Size)
                except Exception:
                    continue
                ent = round(entropy(blob), 3)
                resources.append({"type": type_name, "size": lang.data.struct.Size, "entropy": ent})
                if ent > 7.2 and lang.data.struct.Size > 4096:
                    rep.add("medium", f"High entropy resource ({type_name})", f"{human_size(lang.data.struct.Size)}, entropy {ent} — possible embedded payload.")
                if blob[:2] == b"MZ":
                    rep.add("high", f"Embedded PE file in resource ({type_name})", human_size(lang.data.struct.Size))
    out["resources"] = resources[:100]

    # TLS callbacks
    tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    if tls and getattr(tls.struct, "AddressOfCallBacks", 0):
        out["tls_callbacks"] = hex(tls.struct.AddressOfCallBacks)
        rep.add("medium", "TLS callbacks present", "Code can run before the entry point — a known anti-debug trick.")

    # signature
    sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
    out["signed"] = bool(sec_dir.VirtualAddress and sec_dir.Size)
    if not out["signed"]:
        rep.add("low", "Binary is not Authenticode signed", "")
    else:
        rep.add("info", "Authenticode signature block present", "Signature validity is not verified by this tool.")

    # .NET
    com_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]]
    out["dotnet"] = bool(com_dir.VirtualAddress)

    # overlay
    try:
        offset = pe.get_overlay_data_start_offset()
        if offset and offset < len(data):
            overlay = data[offset:]
            out["overlay"] = {"size": len(overlay), "entropy": round(entropy(overlay), 3)}
            if len(overlay) > 1024 * 100:
                rep.add("medium", "Large overlay appended to the file",
                        f"{human_size(len(overlay))} after the last section, entropy {out['overlay']['entropy']}.")
    except Exception:
        pass

    # debug path
    for dbg in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []:
        pdb = getattr(getattr(dbg, "entry", None), "PdbFileName", None)
        if pdb:
            out["pdb_path"] = pdb.rstrip(b"\x00").decode("latin-1", "ignore")
            break

    pe.close()
    return out


# --------------------------------------------------------------------------- PDF


def analyse_pdf(path, data, rep):
    out = {"version": data[:9].decode("latin-1", "ignore").strip()}
    text = data
    # normalise hex-escaped names like /J#61vaScript
    def deobf(blob: bytes) -> bytes:
        return re.sub(rb"#([0-9a-fA-F]{2})", lambda m: bytes([int(m.group(1), 16)]), blob)

    flat = deobf(text)
    inflated_parts = []
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", text, re.S):
        blob = try_inflate(m.group(1))
        if blob:
            inflated_parts.append(deobf(blob))
    searchable = flat + b"\n" + b"\n".join(inflated_parts)
    out["objects"] = len(re.findall(rb"\d+\s+\d+\s+obj", flat))
    out["streams"] = len(re.findall(rb"\bstream\b", flat))
    out["decompressed_streams"] = len(inflated_parts)

    keywords = {}
    for kw, sev, why in PDF_KEYWORDS:
        count = len(re.findall(re.escape(kw.encode()) + rb"[^a-zA-Z]", searchable))
        if count:
            keywords[kw] = count
            rep.add(sev, f"PDF keyword {kw} x{count}", why)
    out["keywords"] = keywords

    js_blobs = []
    for m in re.finditer(rb"/(?:JS|JavaScript)\s*(?:\((.{0,4000}?)\)|<([0-9a-fA-F\s]{4,8000})>)", searchable, re.S):
        raw = m.group(1) or b""
        if m.group(2):
            try:
                raw = bytes.fromhex(re.sub(rb"\s", b"", m.group(2)).decode())
            except Exception:
                raw = b""
        if raw.strip():
            js_blobs.append(raw.decode("latin-1", "ignore")[:4000])
    # JS held in its own object stream
    for part in inflated_parts:
        if b"eval(" in part or b"unescape(" in part or b"String.fromCharCode" in part:
            js_blobs.append(part.decode("latin-1", "ignore")[:4000])
    out["javascript"] = js_blobs[:20]

    for label, marker, sev, why in [
        ("eval()", rb"eval\s*\(", "high", "Dynamic code evaluation inside PDF JavaScript."),
        ("unescape()", rb"unescape\s*\(", "high", "Shellcode-style unescape decoding."),
        ("String.fromCharCode", rb"String\.fromCharCode", "medium", "Character-code string building (obfuscation)."),
        ("util.printf", rb"util\.print[df]", "high", "Adobe util.printf, a classic exploit primitive."),
        ("exportDataObject", rb"this\.exportDataObject", "high", "Drops an embedded file to disk."),
        ("app.launchURL", rb"app\.launchURL", "high", "Opens a URL without user action."),
        ("Reader exploit APIs", rb"getAnnots|getIcon|spell\.customDictionaryOpen", "medium", "APIs seen in known Reader exploits."),
    ]:
        if re.search(marker, searchable, re.I):
            rep.add(sev, f"PDF JavaScript calls {label}", why)

    if out["objects"] and not keywords:
        rep.add("info", "No active content found in the PDF", f"{out['objects']} objects, no JS/launch/embedded files.")
    return out


# --------------------------------------------------------------------------- Office


def analyse_ole(path, data, rep):
    out = {}
    try:
        from oletools.olevba import VBA_Parser
    except ImportError:
        out["skipped"] = "oletools not installed (pip install oletools)"
        if b"VBA" in data or b"_VBA_PROJECT" in data:
            rep.add("medium", "VBA project markers found in the OLE file", "Install oletools for macro extraction.")
        return out

    try:
        parser = VBA_Parser(str(path))
        out["has_macros"] = bool(parser.detect_vba_macros())
        macros = []
        if out["has_macros"]:
            for _fn, _stream, vba_name, vba_code in parser.extract_macros():
                macros.append({"name": vba_name, "code": vba_code[:20000], "lines": vba_code.count("\n") + 1})
            rep.add("high", "VBA macros present", f"{len(macros)} module(s).")
        out["macros"] = macros
        blob = "\n".join(m["code"] for m in macros)
        auto = sorted({k for k in VBA_AUTOEXEC if k.lower() in blob.lower()})
        susp = sorted({k for k in VBA_SUSPICIOUS if k.lower() in blob.lower()})
        out["autoexec"] = auto
        out["suspicious_keywords"] = susp
        if auto:
            rep.add("high", "Macro runs automatically", ", ".join(auto))
        if susp:
            rep.add("high", "Suspicious macro keywords", ", ".join(susp[:15]))
        try:
            results = parser.analyze_macros()
            out["olevba_findings"] = [
                {"type": r[0], "keyword": r[1], "description": r[2]} for r in (results or [])
            ][:100]
        except Exception:
            pass
        parser.close()
    except Exception as exc:
        out["error"] = str(exc)
    if b"\x00d\x00d\x00e" in data.lower() or b"DDEAUTO" in data.upper():
        rep.add("high", "DDE field markers present", "DDE/DDEAUTO can launch commands without macros.")
    return out


def analyse_ooxml(path, data, rep):
    out = {}
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            out["entries"] = names[:300]
            if any(n.endswith("vbaProject.bin") for n in names):
                rep.add("high", "Document contains a VBA project", "vbaProject.bin present in the OOXML container.")
                out["has_macros"] = True
            externals = []
            for name in names:
                if name.endswith(".rels"):
                    body = zf.read(name).decode("utf-8", "ignore")
                    for m in re.finditer(r'Target="([^"]+)"[^>]*TargetMode="External"', body):
                        externals.append(m.group(1))
                    for m in re.finditer(r'TargetMode="External"[^>]*Target="([^"]+)"', body):
                        externals.append(m.group(1))
            out["external_targets"] = sorted(set(externals))[:100]
            for target in out["external_targets"]:
                if target.lower().startswith(("http", "\\\\", "file:", "mhtml:")):
                    rep.add("high", "External relationship target", f"{defang(target)} — remote template / OLE injection pattern.")
            for name in names:
                if "embeddings/" in name or name.endswith((".bin", ".exe", ".dll", ".scr")):
                    rep.add("medium", f"Embedded object in document: {name}", "")
            body = b"".join(zf.read(n) for n in names if n.endswith(".xml"))[:4_000_000]
            if b"DDEAUTO" in body.upper() or b"ddeauto" in body:
                rep.add("high", "DDEAUTO field in document body", "Executes a command on open in unpatched Office.")
    except Exception as exc:
        out["error"] = str(exc)
    return out


def analyse_archive(path, data, rep):
    out = {}
    try:
        with zipfile.ZipFile(path) as zf:
            items = []
            for info in zf.infolist()[:500]:
                items.append({"name": info.filename, "size": info.file_size, "compressed": info.compress_size,
                              "encrypted": bool(info.flag_bits & 0x1)})
            out["entries"] = items
            if any(i["encrypted"] for i in items):
                rep.add("medium", "Archive is password protected", "Contents cannot be inspected statically.")
            for i in items:
                if i["name"].lower().endswith((".exe", ".scr", ".js", ".vbs", ".lnk", ".bat", ".cmd", ".ps1", ".hta", ".jar", ".iso", ".img")):
                    rep.add("medium", f"Executable content in archive: {i['name']}", "")
                if i["size"] and i["compressed"] and i["size"] / max(i["compressed"], 1) > 500:
                    rep.add("medium", f"Extreme compression ratio: {i['name']}", "Possible zip bomb.")
    except Exception as exc:
        out["error"] = str(exc)
    return out


# --------------------------------------------------------------------------- YARA


def run_yara(path, rules_dir, rep):
    try:
        import yara
    except ImportError:
        return {"skipped": "yara-python not installed (pip install yara-python)"}
    if not rules_dir or not os.path.isdir(rules_dir):
        return {"skipped": f"no rules directory at {rules_dir}"}

    sources = {}
    for root, _dirs, files in os.walk(rules_dir):
        for fn in files:
            if fn.endswith((".yar", ".yara")):
                full = os.path.join(root, fn)
                sources[os.path.relpath(full, rules_dir)] = full
    if not sources:
        return {"skipped": "no .yar files found"}
    try:
        rules = yara.compile(filepaths=sources)
    except Exception as exc:
        return {"error": f"rule compilation failed: {exc}"}

    matches = []
    for m in rules.match(str(path), timeout=60):
        meta = dict(m.meta or {})
        matches.append({"rule": m.rule, "tags": list(m.tags), "meta": meta,
                        "strings": sorted({str(s.identifier) for s in m.strings})[:20]})
        rep.add(str(meta.get("severity", "high")).lower() if meta.get("severity") else "high",
                f"YARA match: {m.rule}", meta.get("description", ""), source="yara")
    return {"matches": matches, "rule_files": sorted(sources)}


# --------------------------------------------------------------------------- driver


def run_static(path, ident, opts):
    rep = Report()
    rep["findings"] = []
    with open(path, "rb") as fh:
        data = fh.read()

    file_entropy = round(entropy(data), 3)
    rep["overview"] = {
        "file_name": os.path.basename(path),
        "file_size": len(data),
        "file_size_h": human_size(len(data)),
        "entropy": file_entropy,
        "type": ident,
        "hashes": hash_file(path),
    }
    rep["entropy_map"] = entropy_map(data)
    if file_entropy > 7.4 and len(data) > 20000:
        rep.add("medium", "Whole-file entropy is very high", f"{file_entropy} — the file is packed, compressed or encrypted.")

    strings = extract_strings(data, min_len=opts.get("min_string_len", 6), limit=opts.get("max_strings", 4000))
    rep["strings"] = strings
    rep["iocs"] = extract_iocs(strings)

    kind = ident["kind"]
    if kind == "pe":
        rep["pe"] = analyse_pe(path, data, rep)
    elif kind == "pdf":
        rep["pdf"] = analyse_pdf(path, data, rep)
    elif kind == "ole":
        rep["office"] = analyse_ole(path, data, rep)
    elif kind in ("docx", "xlsx", "pptx", "ooxml"):
        rep["office"] = analyse_ooxml(path, data, rep)
    elif kind in ("zip", "jar", "apk"):
        rep["archive"] = analyse_archive(path, data, rep)

    if b"MZ" in data[64:] and kind not in ("pe",):
        idx = data.find(b"MZ", 64)
        if data[idx : idx + 256].find(b"This program cannot be run in DOS mode") != -1:
            rep.add("high", "Embedded Windows executable found inside the file", f"at offset {idx}")

    if kind in ("script", "text", "html"):
        lowered = data.lower()
        for marker, sev, why in [
            (b"frombase64string", "high", "Base64 payload decoding."),
            (b"-enc ", "high", "Encoded PowerShell command line."),
            (b"invoke-expression", "high", "PowerShell IEX execution."),
            (b"iex(", "high", "PowerShell IEX execution."),
            (b"downloadstring", "high", "Remote code download."),
            (b"bitsadmin", "medium", "LOLBin download utility."),
            (b"certutil", "medium", "LOLBin decode/download utility."),
            (b"mshta", "medium", "LOLBin HTML application host."),
            (b"schtasks /create", "medium", "Scheduled task persistence."),
            (b"reg add", "medium", "Registry modification."),
            (b"rundll32", "medium", "LOLBin DLL execution."),
            (b"eval(", "medium", "Dynamic evaluation."),
            (b"wscript.shell", "high", "Shell object instantiation."),
            (b"powershell -w hidden", "high", "Hidden-window PowerShell."),
        ]:
            if marker in lowered:
                rep.add(sev, f"Script indicator: {marker.decode()}", why)

    rep["yara"] = run_yara(path, opts.get("rules"), rep)

    score = 0
    for f in rep["findings"]:
        score += SEV_WEIGHT.get(f["severity"], 0)
    rep["score"] = min(100, score)
    rep["verdict"] = verdict_for(rep["score"])
    return rep


def verdict_for(score):
    if score >= 75:
        return "Malicious"
    if score >= 45:
        return "Likely malicious"
    if score >= 20:
        return "Suspicious"
    if score > 0:
        return "Low risk"
    return "No indicators"
