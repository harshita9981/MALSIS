# malsis

File triage for SOC work: static analysis first, optional sandbox detonation second,
one self-contained report at the end.

The tool never runs the sample on your machine. Dynamic analysis means uploading it
to a detonation service (CAPE, Triage, VirusTotal) and reading the behaviour report back.

## Install

```
python3 -m pip install -r requirements.txt
```

Everything is optional. Missing packages disable one module each and say so in the
report rather than crashing: no `pefile` means no PE internals, no `yara-python`
means no signature matching, and so on.

## Use

```
python3 -m malsis sample.exe
python3 -m malsis invoice.pdf -f html -o /cases/1234/invoice.html
python3 -m malsis dropper.ps1 -f json | jq .findings
python3 -m malsis sample.exe --dynamic cape --sandbox-url https://cape.internal --api-key $CAPE_TOKEN
python3 -m malsis sample.exe --dynamic vt --api-key $VT_KEY
```

Formats: `html` (default), `txt`, `json`, `pdf`. HTML is one file with no external
assets, dark-mode aware, and has print styles so browser print-to-PDF gives a clean
document for attaching to a ticket. Native `pdf` needs `weasyprint`.

## Desktop interface

```
python3 -m malsis            # no arguments opens the GUI
python3 run_gui.py            # same thing
python3 -m malsis --gui
```

Tkinter, which ships with Python on macOS and Windows, so there is nothing extra to
install. Add files (or drag them on, if `tkinterdnd2` is installed), set the options
once, and analyse. Each sample gets a row with its type, verdict and score; double-click
a row to open its report. Settings persist between runs in:

- macOS `~/Library/Application Support/malsis/settings.json`
- Windows `%APPDATA%\malsis\settings.json`
- Linux `~/.config/malsis/settings.json`

The API key is only written to that file if you tick "Remember", and it is stored in
plain text (mode 0600 on macOS and Linux). Leaving it unticked means the field is
populated from `malsis_API_KEY` each time, which is the better habit.

Analysis runs on a worker thread, so the window stays responsive through a long sandbox
wait. A sandbox failure marks that row and still writes the static report.

## Building a .app / .exe

```
pip install pyinstaller

# macOS / Linux
pyinstaller --windowed --noconfirm --name malsis \
  --add-data "malsis/rules:malsis/rules" run_gui.py

# Windows
pyinstaller --windowed --noconfirm --name malsis ^
  --add-data "malsis\rules;malsis\rules" run_gui.py
```

Output lands in `dist/`. Build on the platform you are targeting; PyInstaller does not
cross-compile. On macOS the unsigned `.app` needs a right-click > Open the first time, or
`xattr -dr com.apple.quarantine dist/malsis.app`. If you bundle `yara-python`, check the
compiled rules load in the frozen build before you hand it to anyone.

## What it looks at

**Every file** — hashes (MD5/SHA1/SHA256, plus ssdeep and TLSH when installed),
Shannon entropy with a per-block map, printable ASCII and UTF-16 strings, and IOCs
pulled out of those strings (URLs, IPs, domains, emails, Windows paths, registry keys,
mutexes, onion addresses, BTC addresses). Network indicators are defanged in the report.

**PE** — machine type, subsystem, compile timestamp sanity, imphash, section table with
per-section entropy and W+X flags, packer section names, full import table with
suspicious APIs grouped by capability (injection, persistence, keylogging, anti-analysis,
crypto, network, discovery), exports, resources including embedded PE detection, TLS
callbacks, Authenticode presence, .NET flag, overlay, PDB path.

**PDF** — object and stream counts, Flate-decompressed stream contents, active-content
keywords (`/JS`, `/OpenAction`, `/Launch`, `/EmbeddedFile`, `/RichMedia`, `/XFA`,
`/JBIG2Decode` and others, including hex-obfuscated names like `/J#61vaScript`), and
extracted JavaScript with exploit-primitive detection.

**Office** — legacy OLE goes through oletools for macro extraction, auto-run triggers and
suspicious keywords; OOXML is inspected for `vbaProject.bin`, external relationship
targets (remote template injection), embedded objects and DDEAUTO fields.

**Archives** — entry listing, encrypted entries, executable content, compression-ratio bombs.

**Scripts and text** — encoded PowerShell, IEX, download cradles, LOLBin references.

**YARA** — every `.yar` in `malsis/rules` (override with `--rules`). A starter set ships
with the tool; drop your own rules in the same directory and they compile automatically.
Rule `meta.severity` feeds the score.

## Scoring

Each finding carries a severity (high 30, medium 16, low 6, info 0). The sum is capped at
100 and mapped to a verdict: 75+ Malicious, 45+ Likely malicious, 20+ Suspicious,
above 0 Low risk. The weights live in `SEV_WEIGHT` in `static.py` — tune them against your
own corpus, the defaults are a starting point rather than a calibrated model.

## Dynamic backends

| Backend | Flag | Needs |
|---|---|---|
| CAPEv2 / Cuckoo | `--dynamic cape` | `--sandbox-url`, `--api-key` |
| Hatching Triage | `--dynamic triage` | `--api-key` (URL defaults to tria.ge) |
| VirusTotal | `--dynamic vt` | `--api-key`; reads existing detections and behaviour. Add `--vt-upload` to submit unknown samples |

Env vars `malsis_SANDBOX_URL` and `malsis_API_KEY` work instead of the flags.
Use `--insecure` for a self-signed CAPE. A failed sandbox run never loses the static
report; the error is recorded in the dynamic section.

Adding a backend means subclassing `Backend` in `dynamic.py` with `submit`, `wait` and
`normalise`, then registering it in the `BACKENDS` dict. `normalise` should return the
common shape: `score`, `signatures`, `processes`, `network{dns,hosts,http}`, `files`,
`registry`, `mutexes`, `dropped`, `mitre`.

## Handling notes

- Analyse samples on an isolated host. The tool reads files, but you will inevitably be
  handling live malware next to it.
- `--dynamic vt` without `--vt-upload` only looks the hash up, so it will not leak a
  sample that has never been submitted. Uploading to a public sandbox makes the sample
  public; use a private instance for anything customer-related.
- The PE module was written against pefile's API but is exercised by whatever samples you
  run — check the section and resource output on a known-good binary before trusting it
  on a case.
