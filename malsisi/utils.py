"""Hashing, entropy, string extraction, IOC harvesting."""
from __future__ import annotations

import hashlib
import math
import re
import zlib
from collections import Counter

CHUNK = 1 << 20

# --------------------------------------------------------------------------- hashes


def hash_file(path):
    algos = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            for h in algos.values():
                h.update(chunk)
    out = {k: v.hexdigest() for k, v in algos.items()}
    try:  # optional
        import ssdeep  # type: ignore

        out["ssdeep"] = ssdeep.hash_from_file(str(path))
    except Exception:
        pass
    try:  # optional
        import tlsh  # type: ignore

        with open(path, "rb") as fh:
            digest = tlsh.hash(fh.read())
        if digest and digest != "TNULL":
            out["tlsh"] = digest
    except Exception:
        pass
    return out


# --------------------------------------------------------------------------- entropy


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def entropy_map(data: bytes, blocks: int = 64):
    """Coarse entropy per block, for the sparkline in the report."""
    if not data:
        return []
    step = max(1, len(data) // blocks)
    return [round(entropy(data[i : i + step]), 3) for i in range(0, len(data), step)][:blocks]


def try_inflate(data: bytes):
    for wbits in (15, -15, 47):
        try:
            return zlib.decompress(data, wbits)
        except Exception:
            continue
    return None


# --------------------------------------------------------------------------- strings


def extract_strings(data: bytes, min_len: int = 6, limit: int = 4000):
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    wide_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    found = []
    seen = set()
    for match in ascii_re.finditer(data):
        s = match.group().decode("ascii", "ignore")
        if s not in seen:
            seen.add(s)
            found.append(s)
        if len(found) >= limit:
            break
    for match in wide_re.finditer(data):
        s = match.group().decode("utf-16-le", "ignore")
        if s not in seen:
            seen.add(s)
            found.append(s)
        if len(found) >= limit:
            break
    return found


# --------------------------------------------------------------------------- IOCs

TLDS = (
    "com|net|org|info|biz|io|co|ru|cn|br|de|uk|fr|nl|eu|top|xyz|online|site|shop|club|live|"
    "icu|cc|tk|ml|ga|cf|gq|su|pw|ws|me|tv|in|pl|ir|kr|jp|it|es|se|no|fi|dk|ch|at|be|cz|ua|"
    "tr|vn|id|th|my|sg|hk|tw|au|nz|ca|mx|ar|cl|za|ng|ke|app|dev|cloud|link|space|website|fun|life"
)

PATTERNS = {
    "url": re.compile(r"\b(?:https?|ftp)://[^\s\"'<>)\]\\}]{4,}", re.I),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b"),
    "domain": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:%s)\b" % TLDS, re.I),
    "win_path": re.compile(r"""\b[a-zA-Z]:\\[^\s"'<>|*?]{3,160}"""),
    "registry": re.compile(r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR)\\\\?[^\s\"'<>|]{4,120}", re.I),
    "bitcoin": re.compile(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,62})\b"),
    "mutex": re.compile(r"\b(?:Global|Local)\\\\?[A-Za-z0-9_\-{}]{4,60}"),
    "onion": re.compile(r"\b[a-z2-7]{16,56}\.onion\b", re.I),
}

# Things that match the domain regex but never mean anything.
DOMAIN_NOISE = re.compile(
    r"\.(?:dll|exe|sys|bat|cmd|tmp|dat|bin|inf|ini|log|xml|json|html|css|node|obj|lib|pdb|res)$",
    re.I,
)
IP_NOISE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1|255\.255\.255\.\d+|1\.2\.3\.4|\d\.\d\.\d\.\d)$")


def extract_iocs(strings):
    blob = "\n".join(strings) if isinstance(strings, (list, tuple)) else str(strings)
    out = {}
    for name, rx in PATTERNS.items():
        hits = set()
        for m in rx.finditer(blob):
            value = m.group().strip().rstrip(".,;:")
            if name == "domain" and (DOMAIN_NOISE.search(value) or len(value) < 6):
                continue
            if name == "ipv4" and IP_NOISE.match(value):
                continue
            if len(value) > 300:
                continue
            hits.add(value)
        if hits:
            out[name] = sorted(hits)[:200]
    # domains already covered by a URL or email are noise in the table
    if "domain" in out and (out.get("url") or out.get("email")):
        joined = " ".join(out.get("url", []) + out.get("email", [])).lower()
        out["domain"] = [d for d in out["domain"] if d.lower() not in joined]
        if not out["domain"]:
            del out["domain"]
    return out


def defang(value: str) -> str:
    return (
        value.replace("http://", "hxxp://")
        .replace("https://", "hxxps://")
        .replace("ftp://", "fxp://")
        .replace(".", "[.]")
        .replace("@", "[@]")
    )


def human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return str(n)
