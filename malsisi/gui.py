"""Desktop interface. Tkinter only, so it runs on macOS, Windows and Linux
with a stock Python install and packages cleanly with PyInstaller.
"""
from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
import traceback
import webbrowser

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import __version__
from .engine import DEFAULT_RULES, analyse
from .report import render

BACKENDS = ["none", "cape", "triage", "vt"]
FORMATS = ["html", "txt", "json", "pdf"]
VERDICT_COLOR = {
    "Malicious": "#b32318",
    "Likely malicious": "#c2401a",
    "Suspicious": "#a35c06",
    "Low risk": "#5b6670",
    "No indicators": "#1f6b3a",
}


# --------------------------------------------------------------------------- config


def config_path():
    if sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support/malysis")
    elif os.name == "nt":
        base = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "malysis")
    else:
        base = os.path.join(os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config")), "malysis")
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, "settings.json")


def load_config():
    try:
        with open(config_path(), encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def save_config(data):
    path = config_path()
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        if os.name != "nt":
            os.chmod(path, 0o600)
    except Exception:
        pass


def reveal(path):
    """Show a file in Finder / Explorer / the desktop file manager."""
    try:
        if sys.platform == "darwin":
            subprocess.run(["open", "-R", path], check=False)
        elif os.name == "nt":
            subprocess.run(["explorer", "/select,", os.path.normpath(path)], check=False)
        else:
            subprocess.run(["xdg-open", os.path.dirname(path)], check=False)
    except Exception:
        pass


# --------------------------------------------------------------------------- app


class App:
    def __init__(self, root):
        self.root = root
        self.cfg = load_config()
        self.queue: "queue.Queue" = queue.Queue()
        self.samples = []      # list of file paths, index matches tree iid
        self.results = {}      # sample path -> (result, report_path)
        self.running = False

        root.title(f"malysis {__version__}")
        root.minsize(820, 620)
        self._build()
        self._restore()
        root.protocol("WM_DELETE_WINDOW", self._on_close)
        root.after(120, self._drain)

    # ---------------------------------------------------------------- layout

    def _build(self):
        pad = {"padx": 10, "pady": 6}
        outer = ttk.Frame(self.root, padding=12)
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(1, weight=3)
        outer.rowconfigure(4, weight=2)

        # --- file picker row
        top = ttk.Frame(outer)
        top.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Button(top, text="Add files\u2026", command=self.add_files).pack(side="left")
        ttk.Button(top, text="Remove selected", command=self.remove_selected).pack(side="left", padx=(6, 0))
        ttk.Button(top, text="Clear", command=self.clear_files).pack(side="left", padx=(6, 0))
        self.drop_hint = ttk.Label(top, text="", foreground="#6b7580")
        self.drop_hint.pack(side="left", padx=(12, 0))

        # --- sample table
        cols = ("type", "verdict", "score", "report")
        self.tree = ttk.Treeview(outer, columns=cols, show="tree headings", height=8,
                                 selectmode="extended")
        self.tree.heading("#0", text="File")
        self.tree.heading("type", text="Type")
        self.tree.heading("verdict", text="Verdict")
        self.tree.heading("score", text="Score")
        self.tree.heading("report", text="Report")
        self.tree.column("#0", width=250, stretch=True)
        self.tree.column("type", width=170, stretch=False)
        self.tree.column("verdict", width=130, stretch=False)
        self.tree.column("score", width=55, anchor="e", stretch=False)
        self.tree.column("report", width=180, stretch=True)
        self.tree.grid(row=1, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(outer, orient="vertical", command=self.tree.yview)
        scroll.grid(row=1, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.bind("<Double-1>", lambda _e: self.open_report())
        for verdict, colour in VERDICT_COLOR.items():
            self.tree.tag_configure(verdict, foreground=colour)

        # --- options
        opts = ttk.LabelFrame(outer, text="Options", padding=10)
        opts.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        for col in (1, 3, 5):
            opts.columnconfigure(col, weight=1)

        self.fmt = tk.StringVar(value="html")
        self.rules = tk.StringVar(value=DEFAULT_RULES)
        self.backend = tk.StringVar(value="none")
        self.sandbox_url = tk.StringVar()
        self.api_key = tk.StringVar()
        self.remember_key = tk.BooleanVar(value=False)
        self.vt_upload = tk.BooleanVar(value=False)
        self.insecure = tk.BooleanVar(value=False)
        self.timeout = tk.StringVar(value="900")
        self.outdir = tk.StringVar(value="")

        ttk.Label(opts, text="Report format").grid(row=0, column=0, sticky="w", padx=(0, 6))
        ttk.Combobox(opts, textvariable=self.fmt, values=FORMATS, state="readonly", width=8) \
            .grid(row=0, column=1, sticky="w")

        ttk.Label(opts, text="Save reports to").grid(row=0, column=2, sticky="w", padx=(16, 6))
        ttk.Entry(opts, textvariable=self.outdir).grid(row=0, column=3, columnspan=2, sticky="ew")
        ttk.Button(opts, text="\u2026", width=3, command=self.pick_outdir).grid(row=0, column=5, sticky="w", padx=(4, 0))

        ttk.Label(opts, text="YARA rules").grid(row=1, column=0, sticky="w", pady=(8, 0), padx=(0, 6))
        ttk.Entry(opts, textvariable=self.rules).grid(row=1, column=1, columnspan=4, sticky="ew", pady=(8, 0))
        ttk.Button(opts, text="\u2026", width=3, command=self.pick_rules).grid(row=1, column=5, sticky="w", pady=(8, 0), padx=(4, 0))

        ttk.Separator(opts, orient="horizontal").grid(row=2, column=0, columnspan=6, sticky="ew", pady=10)

        ttk.Label(opts, text="Sandbox").grid(row=3, column=0, sticky="w", padx=(0, 6))
        self.backend_box = ttk.Combobox(opts, textvariable=self.backend, values=BACKENDS,
                                        state="readonly", width=8)
        self.backend_box.grid(row=3, column=1, sticky="w")
        self.backend_box.bind("<<ComboboxSelected>>", lambda _e: self._sync_sandbox_fields())

        ttk.Label(opts, text="Timeout (s)").grid(row=3, column=2, sticky="e", padx=(16, 6))
        ttk.Entry(opts, textvariable=self.timeout, width=8).grid(row=3, column=3, sticky="w")

        self.url_label = ttk.Label(opts, text="Sandbox URL")
        self.url_label.grid(row=4, column=0, sticky="w", pady=(8, 0), padx=(0, 6))
        self.url_entry = ttk.Entry(opts, textvariable=self.sandbox_url)
        self.url_entry.grid(row=4, column=1, columnspan=5, sticky="ew", pady=(8, 0))

        self.key_label = ttk.Label(opts, text="API key")
        self.key_label.grid(row=5, column=0, sticky="w", pady=(8, 0), padx=(0, 6))
        self.key_entry = ttk.Entry(opts, textvariable=self.api_key, show="\u2022")
        self.key_entry.grid(row=5, column=1, columnspan=3, sticky="ew", pady=(8, 0))
        self.remember_box = ttk.Checkbutton(opts, text="Remember (stored in plain text)",
                                            variable=self.remember_key)
        self.remember_box.grid(row=5, column=4, columnspan=2, sticky="w", padx=(8, 0), pady=(8, 0))

        self.vt_box = ttk.Checkbutton(opts, text="Upload to VirusTotal if the hash is unknown",
                                      variable=self.vt_upload)
        self.vt_box.grid(row=6, column=1, columnspan=3, sticky="w", pady=(8, 0))
        self.tls_box = ttk.Checkbutton(opts, text="Skip TLS verification", variable=self.insecure)
        self.tls_box.grid(row=6, column=4, columnspan=2, sticky="w", pady=(8, 0))

        # --- action row
        actions = ttk.Frame(outer)
        actions.grid(row=3, column=0, sticky="ew", pady=(12, 6))
        self.run_btn = ttk.Button(actions, text="Analyse", command=self.start)
        self.run_btn.pack(side="left")
        ttk.Button(actions, text="Open report", command=self.open_report).pack(side="left", padx=(6, 0))
        ttk.Button(actions, text="Show in folder", command=self.show_in_folder).pack(side="left", padx=(6, 0))
        ttk.Button(actions, text="Copy SHA-256", command=self.copy_hash).pack(side="left", padx=(6, 0))
        self.progress = ttk.Progressbar(actions, mode="determinate", length=180)
        self.progress.pack(side="right")
        self.status = ttk.Label(actions, text="Ready")
        self.status.pack(side="right", padx=(0, 10))

        # --- log
        logframe = ttk.LabelFrame(outer, text="Activity", padding=6)
        logframe.grid(row=4, column=0, sticky="nsew")
        logframe.columnconfigure(0, weight=1)
        logframe.rowconfigure(0, weight=1)
        self.log = tk.Text(logframe, height=9, wrap="word", relief="flat", borderwidth=0)
        self.log.grid(row=0, column=0, sticky="nsew")
        logscroll = ttk.Scrollbar(logframe, orient="vertical", command=self.log.yview)
        logscroll.grid(row=0, column=1, sticky="ns")
        self.log.configure(yscrollcommand=logscroll.set, state="disabled")

        ttk.Label(outer, text="Samples are never executed here. Dynamic analysis uploads the file "
                              "to the sandbox you configure.", foreground="#6b7580") \
            .grid(row=5, column=0, sticky="w", pady=(8, 0))

        self._sync_sandbox_fields()

    # ---------------------------------------------------------------- settings

    def _restore(self):
        c = self.cfg
        self.fmt.set(c.get("format", "html"))
        self.rules.set(c.get("rules", DEFAULT_RULES))
        self.backend.set(c.get("backend", "none"))
        self.sandbox_url.set(c.get("sandbox_url", os.environ.get("MALYSIS_SANDBOX_URL", "")))
        self.outdir.set(c.get("outdir", ""))
        self.timeout.set(str(c.get("timeout", 900)))
        self.insecure.set(bool(c.get("insecure", False)))
        key = c.get("api_key") or os.environ.get("MALYSIS_API_KEY", "")
        self.api_key.set(key)
        self.remember_key.set(bool(c.get("api_key")))
        self._sync_sandbox_fields()

    def _collect(self):
        return {
            "format": self.fmt.get(),
            "rules": self.rules.get(),
            "backend": self.backend.get(),
            "sandbox_url": self.sandbox_url.get(),
            "outdir": self.outdir.get(),
            "timeout": self._timeout(),
            "insecure": self.insecure.get(),
            "api_key": self.api_key.get() if self.remember_key.get() else "",
        }

    def _timeout(self):
        try:
            return max(30, int(self.timeout.get()))
        except ValueError:
            return 900

    def _on_close(self):
        save_config(self._collect())
        self.root.destroy()

    def _sync_sandbox_fields(self):
        backend = self.backend.get()
        needs_url = backend == "cape"
        needs_key = backend in ("cape", "triage", "vt")
        for widget in (self.url_label, self.url_entry):
            widget.configure(state="normal" if needs_url else "disabled")
        for widget in (self.key_label, self.key_entry, self.remember_box):
            widget.configure(state="normal" if needs_key else "disabled")
        self.vt_box.configure(state="normal" if backend == "vt" else "disabled")
        self.tls_box.configure(state="normal" if needs_url else "disabled")

    # ---------------------------------------------------------------- files

    def add_files(self, paths=None):
        if paths is None:
            paths = filedialog.askopenfilenames(title="Choose samples")
        for path in paths or []:
            path = os.path.abspath(path)
            if not os.path.isfile(path) or path in self.samples:
                continue
            idx = len(self.samples)
            self.samples.append(path)
            self.tree.insert("", "end", iid=str(idx), text=os.path.basename(path),
                             values=("", "queued", "", ""))
        self._update_status()

    def remove_selected(self):
        if self.running:
            return
        keep = [p for i, p in enumerate(self.samples) if str(i) not in self.tree.selection()]
        self.samples = []
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.add_files(keep)
        for idx, path in enumerate(self.samples):   # restore rows that were already analysed
            if path in self.results:
                self._show_result(idx, *self.results[path])

    def clear_files(self):
        if self.running:
            return
        self.samples = []
        self.results = {}
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._update_status()

    def pick_rules(self):
        chosen = filedialog.askdirectory(title="YARA rules directory")
        if chosen:
            self.rules.set(chosen)

    def pick_outdir(self):
        chosen = filedialog.askdirectory(title="Where to save reports")
        if chosen:
            self.outdir.set(chosen)

    def _selected_index(self):
        selection = self.tree.selection()
        return int(selection[0]) if selection else None

    def _selected_result(self):
        idx = self._selected_index()
        if idx is None or idx >= len(self.samples):
            return None
        return self.results.get(self.samples[idx])

    def open_report(self):
        entry = self._selected_result()
        if not entry:
            self._say("Select a finished sample first.")
            return
        path = entry[1]
        if self.fmt.get() in ("html", "pdf"):
            webbrowser.open("file://" + path)
        else:
            reveal(path)

    def show_in_folder(self):
        entry = self._selected_result()
        if entry:
            reveal(entry[1])
            return
        idx = self._selected_index()
        if idx is not None and idx < len(self.samples):
            reveal(self.samples[idx])

    def copy_hash(self):
        entry = self._selected_result()
        if not entry:
            self._say("Select a finished sample first.")
            return
        digest = entry[0]["static"]["overview"]["hashes"]["sha256"]
        self.root.clipboard_clear()
        self.root.clipboard_append(digest)
        self._say(f"Copied {digest}")

    # ---------------------------------------------------------------- run

    def start(self):
        if self.running:
            return
        if not self.samples:
            self.add_files()
            if not self.samples:
                return
        backend = self.backend.get()
        if backend in ("cape",) and not self.sandbox_url.get().strip():
            messagebox.showerror("Sandbox URL missing", "CAPE needs a base URL, for example https://cape.internal")
            return
        if backend in ("cape", "triage", "vt") and not self.api_key.get().strip():
            messagebox.showerror("API key missing", f"{backend} needs an API key.")
            return

        save_config(self._collect())
        self.running = True
        self.run_btn.configure(state="disabled", text="Analysing\u2026")
        self.progress.configure(maximum=len(self.samples), value=0)
        options = {
            "rules": self.rules.get() or DEFAULT_RULES,
            "dynamic": backend,
            "sandbox_url": self.sandbox_url.get().strip() or None,
            "api_key": self.api_key.get().strip() or None,
            "timeout": self._timeout(),
            "insecure": self.insecure.get(),
            "vt_upload": self.vt_upload.get(),
        }
        fmt = self.fmt.get()
        outdir = self.outdir.get().strip()
        worker = threading.Thread(target=self._work, args=(list(self.samples), options, fmt, outdir), daemon=True)
        worker.start()

    def _work(self, samples, options, fmt, outdir):
        for idx, path in enumerate(samples):
            self.queue.put(("state", idx, "running"))
            try:
                result = analyse(path, progress=lambda m, i=idx: self.queue.put(("log", i, m)), **options)
                name = os.path.basename(path) + f".report.{fmt}"
                out = os.path.join(outdir, name) if outdir else f"{path}.report.{fmt}"
                render(result, fmt, out)
                self.queue.put(("done", idx, (result, out)))
            except Exception as exc:
                self.queue.put(("log", idx, traceback.format_exc(limit=3)))
                self.queue.put(("failed", idx, str(exc)))
        self.queue.put(("finished", None, None))

    def _drain(self):
        try:
            while True:
                kind, idx, payload = self.queue.get_nowait()
                if kind == "log":
                    self._say(f"{os.path.basename(self.samples[idx])}: {payload}")
                elif kind == "state":
                    self.tree.set(str(idx), "verdict", payload)
                elif kind == "done":
                    result, out = payload
                    self.results[self.samples[idx]] = (result, out)
                    self._show_result(idx, result, out)
                    self.progress.step(1)
                elif kind == "failed":
                    self.tree.set(str(idx), "verdict", "error")
                    self.tree.set(str(idx), "report", str(payload)[:80])
                    self.progress.step(1)
                elif kind == "finished":
                    self.running = False
                    self.run_btn.configure(state="normal", text="Analyse")
                    self._say("Done.")
                    self._update_status()
        except queue.Empty:
            pass
        self.root.after(120, self._drain)

    def _show_result(self, idx, result, out):
        verdict = result["verdict"]
        self.tree.item(str(idx), tags=(verdict,))
        self.tree.set(str(idx), "type", result["static"]["overview"]["type"]["label"])
        self.tree.set(str(idx), "verdict", verdict)
        self.tree.set(str(idx), "score", result["score"])
        self.tree.set(str(idx), "report", os.path.basename(out))

    def _say(self, message):
        self.log.configure(state="normal")
        self.log.insert("end", message.rstrip() + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _update_status(self):
        done = sum(1 for p in self.samples if p in self.results)
        self.status.configure(text=f"{len(self.samples)} sample(s), {done} analysed")


# --------------------------------------------------------------------------- launch


def launch():
    try:
        from tkinterdnd2 import DND_FILES, TkinterDnD  # type: ignore

        root = TkinterDnD.Tk()
        dnd = True
    except Exception:
        root = tk.Tk()
        dnd = False

    try:
        ttk.Style().theme_use("aqua" if sys.platform == "darwin" else "vista" if os.name == "nt" else "clam")
    except Exception:
        pass

    app = App(root)
    if dnd:
        app.drop_hint.configure(text="or drag files onto the window")
        root.drop_target_register(DND_FILES)
        root.dnd_bind("<<Drop>>", lambda e: app.add_files(root.tk.splitlist(e.data)))
    else:
        app.drop_hint.configure(text="install tkinterdnd2 for drag and drop")

    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(launch())
