"""File type identification from magic bytes, with an optional libmagic assist."""
from __future__ import annotations

import os
import zipfile

SIGNATURES = [
    (b"MZ", "pe", "DOS/PE executable"),
    (b"\x7fELF", "elf", "ELF executable"),
    (b"%PDF", "pdf", "PDF document"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole", "OLE2 compound file (legacy Office/MSI)"),
    (b"PK\x03\x04", "zip", "ZIP container"),
    (b"Rar!\x1a\x07", "rar", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7z", "7-Zip archive"),
    (b"\x1f\x8b", "gzip", "gzip stream"),
    (b"\xfd7zXZ", "xz", "xz archive"),
    (b"ustar", "tar", "tar archive"),
    (b"\xca\xfe\xba\xbe", "macho", "Mach-O fat binary or Java class"),
    (b"\xcf\xfa\xed\xfe", "macho", "Mach-O 64-bit"),
    (b"\xce\xfa\xed\xfe", "macho", "Mach-O 32-bit"),
    (b"ITSF", "chm", "Compiled HTML Help"),
    (b"MSCF", "cab", "Microsoft Cabinet"),
    (b"\x4c\x00\x00\x00\x01\x14\x02\x00", "lnk", "Windows shortcut"),
    (b"\x25\x21\x50\x53", "ps", "PostScript"),
    (b"OTTO", "font", "OpenType font"),
    (b"\x89PNG", "image", "PNG image"),
    (b"\xff\xd8\xff", "image", "JPEG image"),
    (b"GIF8", "image", "GIF image"),
]

SCRIPT_HINTS = [
    (b"#!", "script", "Shell script"),
    (b"<?php", "script", "PHP source"),
    (b"<script", "script", "HTML/JS"),
    (b"<html", "html", "HTML document"),
    (b"<!DOCTYPE html", "html", "HTML document"),
    (b"@echo off", "script", "Batch script"),
    (b"function ", "script", "Script source"),
    (b"import ", "script", "Script source"),
    (b"param(", "script", "PowerShell script"),
    (b"$erroractionpreference", "script", "PowerShell script"),
    (b"invoke-", "script", "PowerShell script"),
    (b"new-object", "script", "PowerShell script"),
    (b"<job", "script", "Windows Script Host job"),
    (b"createobject", "script", "Script source"),
]

OOXML_MARKERS = {
    "word/": ("docx", "Word document (OOXML)"),
    "xl/": ("xlsx", "Excel workbook (OOXML)"),
    "ppt/": ("pptx", "PowerPoint deck (OOXML)"),
}


def _zip_kind(path):
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
    except Exception:
        return None
    joined = "\n".join(names)
    if "AndroidManifest.xml" in joined:
        return "apk", "Android package"
    if "[Content_Types].xml" in joined:
        for prefix, (kind, label) in OOXML_MARKERS.items():
            if any(n.startswith(prefix) for n in names):
                return kind, label
        return "ooxml", "OOXML container"
    if "META-INF/MANIFEST.MF" in joined:
        return "jar", "Java archive"
    return None


def identify(path):
    with open(path, "rb") as fh:
        head = fh.read(8192)

    kind, label = "unknown", "Unrecognised binary"
    for magic, k, desc in SIGNATURES:
        if head.startswith(magic) or (magic == b"ustar" and head[257:262] == b"ustar"):
            kind, label = k, desc
            break

    if kind == "zip":
        refined = _zip_kind(path)
        if refined:
            kind, label = refined

    if kind == "unknown":
        printable = sum(1 for b in head if 9 <= b <= 13 or 32 <= b <= 126)
        if head and printable / len(head) > 0.90:
            kind, label = "text", "Plain text"
            lowered = head[:2048].lower()
            for marker, k, desc in SCRIPT_HINTS:
                if marker.lower() in lowered:
                    kind, label = k, desc
                    break

    ext = os.path.splitext(str(path))[1].lower()
    if kind in ("text", "script", "unknown"):
        by_ext = {
            ".ps1": "PowerShell script", ".psm1": "PowerShell module", ".vbs": "VBScript",
            ".js": "JavaScript", ".jse": "Encoded JScript", ".wsf": "Windows Script File",
            ".bat": "Batch script", ".cmd": "Batch script", ".hta": "HTML application",
            ".py": "Python script", ".sh": "Shell script", ".php": "PHP source",
            ".reg": "Registry script", ".lnk": "Windows shortcut", ".iqy": "Excel web query",
        }
        if ext in by_ext:
            kind, label = "script", by_ext[ext]

    result = {"kind": kind, "label": label, "magic": head[:8].hex(" ")}

    try:  # optional, nicer labels when available
        import magic as libmagic  # type: ignore

        result["libmagic"] = libmagic.from_file(str(path))
        result["mime"] = libmagic.from_file(str(path), mime=True)
    except Exception:
        pass
    return result
