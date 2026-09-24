"""Dynamic analysis: submit the sample to a sandbox and normalise the behaviour report.

This module never executes the sample on the host running the tool. It only uploads
it to a detonation service and reads the result back.
"""
from __future__ import annotations

import os
import time

from .utils import defang


class SandboxError(RuntimeError):
    pass


def _requests():
    try:
        import requests
    except ImportError as exc:  # pragma: no cover
        raise SandboxError("the requests package is required for dynamic analysis") from exc
    return requests


class Backend:
    name = "base"

    def __init__(self, url=None, api_key=None, timeout=600, poll=15, verify=True, extra=None):
        self.url = (url or "").rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.poll = poll
        self.verify = verify
        self.extra = extra or {}

    def run(self, path):
        task_id = self.submit(path)
        report = self.wait(task_id)
        result = self.normalise(report)
        result["backend"] = self.name
        result["task_id"] = task_id
        return result

    def submit(self, path):
        raise NotImplementedError

    def wait(self, task_id):
        raise NotImplementedError

    def normalise(self, report):
        raise NotImplementedError


# --------------------------------------------------------------------------- CAPE


class CAPE(Backend):
    """CAPEv2 / Cuckoo-style REST API."""

    name = "cape"

    def _headers(self):
        return {"Authorization": f"Token {self.api_key}"} if self.api_key else {}

    def submit(self, path):
        requests = _requests()
        with open(path, "rb") as fh:
            data = {k: v for k, v in self.extra.items()}
            resp = requests.post(
                f"{self.url}/apiv2/tasks/create/file/",
                files={"file": (os.path.basename(path), fh)},
                data=data, headers=self._headers(), verify=self.verify, timeout=120,
            )
        resp.raise_for_status()
        body = resp.json()
        ids = body.get("data", {}).get("task_ids") or []
        task_id = ids[0] if ids else body.get("data", {}).get("task_id") or body.get("task_id")
        if not task_id:
            raise SandboxError(f"CAPE did not return a task id: {body}")
        return task_id

    def wait(self, task_id):
        requests = _requests()
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            resp = requests.get(f"{self.url}/apiv2/tasks/status/{task_id}/",
                                headers=self._headers(), verify=self.verify, timeout=60)
            status = (resp.json() or {}).get("data")
            if status in ("reported", "completed"):
                break
            if status in ("failed_analysis", "failed_processing", "failed_reporting"):
                raise SandboxError(f"CAPE task {task_id} failed with status {status}")
            time.sleep(self.poll)
        else:
            raise SandboxError(f"timed out after {self.timeout}s waiting for CAPE task {task_id}")

        resp = requests.get(f"{self.url}/apiv2/tasks/get/report/{task_id}/json/",
                            headers=self._headers(), verify=self.verify, timeout=300)
        resp.raise_for_status()
        return resp.json()

    def normalise(self, report):
        body = report.get("data", report) if isinstance(report, dict) else {}
        info = body.get("info", {})
        out = {
            "score": info.get("score"),
            "url": f"{self.url}/analysis/{info.get('id')}/" if info.get("id") else None,
            "duration": info.get("duration"),
            "signatures": [
                {"name": s.get("name"), "description": s.get("description"),
                 "severity": s.get("severity"), "confidence": s.get("confidence")}
                for s in body.get("signatures", [])
            ],
            "mitre": sorted({t for s in body.get("signatures", []) for t in (s.get("ttp") or {})}),
            "processes": [],
            "network": {},
            "dropped": [],
            "registry": [],
            "files": [],
        }
        for proc in body.get("behavior", {}).get("processes", [])[:200]:
            out["processes"].append({
                "pid": proc.get("process_id"), "ppid": proc.get("parent_id"),
                "name": proc.get("process_name"), "cmdline": proc.get("command_line"),
            })
        summary = body.get("behavior", {}).get("summary", {})
        out["files"] = (summary.get("write_files") or summary.get("file_written") or [])[:300]
        out["registry"] = (summary.get("write_keys") or summary.get("regkey_written") or [])[:300]
        out["mutexes"] = (summary.get("mutexes") or summary.get("mutex") or [])[:100]
        net = body.get("network", {})
        out["network"] = {
            "dns": [d.get("request") for d in net.get("dns", [])][:200],
            "hosts": [h if isinstance(h, str) else h.get("ip") for h in net.get("hosts", [])][:200],
            "http": [f"{h.get('method', 'GET')} {h.get('uri')}" for h in net.get("http", []) + net.get("http_ex", [])][:200],
        }
        out["dropped"] = [
            {"name": d.get("name"), "sha256": d.get("sha256"), "type": d.get("type")}
            for d in body.get("dropped", [])[:200]
        ]
        return out


# --------------------------------------------------------------------------- Triage


class Triage(Backend):
    """Hatching Triage (tria.ge) public or private cloud."""

    name = "triage"
    DEFAULT_URL = "https://tria.ge/api"

    def _headers(self):
        return {"Authorization": f"Bearer {self.api_key}"}

    def submit(self, path):
        requests = _requests()
        base = self.url or self.DEFAULT_URL
        with open(path, "rb") as fh:
            resp = requests.post(
                f"{base}/v0/samples",
                headers=self._headers(),
                files={"file": (os.path.basename(path), fh)},
                data={"_json": '{"kind":"file","interactive":false}'},
                timeout=180,
            )
        resp.raise_for_status()
        return resp.json()["id"]

    def wait(self, sample_id):
        requests = _requests()
        base = self.url or self.DEFAULT_URL
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            resp = requests.get(f"{base}/v0/samples/{sample_id}", headers=self._headers(), timeout=60)
            resp.raise_for_status()
            status = resp.json().get("status")
            if status == "reported":
                break
            if status in ("failed",):
                raise SandboxError(f"Triage sample {sample_id} failed")
            time.sleep(self.poll)
        else:
            raise SandboxError(f"timed out after {self.timeout}s waiting for Triage sample {sample_id}")
        resp = requests.get(f"{base}/v0/samples/{sample_id}/overview.json", headers=self._headers(), timeout=120)
        resp.raise_for_status()
        return resp.json()

    def normalise(self, report):
        analysis = report.get("analysis", {})
        targets = report.get("targets", [])
        sigs = report.get("signatures", []) or [s for t in targets for s in t.get("signatures", [])]
        out = {
            "score": analysis.get("score"),
            "url": f"https://tria.ge/{report.get('sample', {}).get('id', '')}",
            "family": sorted({f for f in (report.get("analysis", {}).get("family") or [])}),
            "signatures": [
                {"name": s.get("name"), "description": s.get("desc") or s.get("name"), "severity": s.get("score")}
                for s in sigs
            ],
            "mitre": sorted({t for s in sigs for t in (s.get("ttp") or [])}),
            "processes": [
                {"pid": p.get("pid"), "ppid": p.get("ppid"), "name": p.get("image"), "cmdline": p.get("cmd")}
                for t in targets for p in (t.get("processes") or [])
            ][:200],
            "network": {
                "dns": sorted({d.get("domain") for d in (report.get("extracted", []) or []) if d.get("domain")}) or
                       sorted({h for t in targets for h in (t.get("iocs", {}).get("domains") or [])}),
                "hosts": sorted({h for t in targets for h in (t.get("iocs", {}).get("ips") or [])}),
                "http": sorted({u for t in targets for u in (t.get("iocs", {}).get("urls") or [])}),
            },
            "dropped": [],
            "registry": [],
            "files": [],
            "config": [e.get("config") for e in (report.get("extracted") or []) if e.get("config")],
        }
        return out


# --------------------------------------------------------------------------- VirusTotal


class VirusTotal(Backend):
    """Reads existing VT detections and behaviour. Uploads only when allowed."""

    name = "virustotal"
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, *args, **kwargs):
        self.allow_upload = kwargs.pop("allow_upload", False)
        super().__init__(*args, **kwargs)

    def _headers(self):
        return {"x-apikey": self.api_key}

    def run(self, path):
        requests = _requests()
        from .utils import hash_file

        sha256 = hash_file(path)["sha256"]
        resp = requests.get(f"{self.BASE}/files/{sha256}", headers=self._headers(), timeout=60)
        if resp.status_code == 404:
            if not self.allow_upload:
                return {"backend": self.name, "task_id": sha256, "not_found": True,
                        "note": "Sample is unknown to VirusTotal. Re-run with --vt-upload to submit it."}
            with open(path, "rb") as fh:
                up = requests.post(f"{self.BASE}/files", headers=self._headers(),
                                   files={"file": (os.path.basename(path), fh)}, timeout=300)
            up.raise_for_status()
            deadline = time.time() + self.timeout
            while time.time() < deadline:
                time.sleep(self.poll)
                resp = requests.get(f"{self.BASE}/files/{sha256}", headers=self._headers(), timeout=60)
                if resp.status_code == 200:
                    break
            else:
                raise SandboxError("timed out waiting for VirusTotal analysis")
        resp.raise_for_status()
        attrs = resp.json()["data"]["attributes"]

        behaviour = {}
        try:
            b = requests.get(f"{self.BASE}/files/{sha256}/behaviour_summary", headers=self._headers(), timeout=120)
            if b.status_code == 200:
                behaviour = b.json().get("data", {})
        except Exception:
            pass

        stats = attrs.get("last_analysis_stats", {})
        total = sum(v for v in stats.values() if isinstance(v, int)) or 1
        return {
            "backend": self.name,
            "task_id": sha256,
            "url": f"https://www.virustotal.com/gui/file/{sha256}",
            "score": round(100 * stats.get("malicious", 0) / total),
            "detections": f"{stats.get('malicious', 0)}/{total}",
            "names": (attrs.get("names") or [])[:20],
            "family": sorted({v.get("result") for v in (attrs.get("last_analysis_results") or {}).values()
                              if v.get("result")})[:20],
            "signatures": [{"name": t, "description": ""} for t in (behaviour.get("verdicts") or [])],
            "mitre": sorted({t for t in (behaviour.get("mitre_attack_techniques") or [])
                             if isinstance(t, str)}),
            "processes": [{"cmdline": c} for c in (behaviour.get("command_executions") or [])[:200]],
            "network": {
                "dns": [d.get("hostname") for d in (behaviour.get("dns_lookups") or []) if d.get("hostname")][:200],
                "hosts": (behaviour.get("ip_traffic") and [i.get("destination_ip") for i in behaviour["ip_traffic"]][:200]) or [],
                "http": [h.get("url") for h in (behaviour.get("http_conversations") or [])][:200],
            },
            "files": (behaviour.get("files_written") or [])[:300],
            "registry": (behaviour.get("registry_keys_set") or [])[:300],
            "mutexes": (behaviour.get("mutexes_created") or [])[:100],
            "dropped": [],
        }


BACKENDS = {"cape": CAPE, "triage": Triage, "vt": VirusTotal, "virustotal": VirusTotal}


def build_backend(name, *, url=None, api_key=None, timeout=900, poll=15,
                  insecure=False, vt_upload=False):
    cls = BACKENDS.get(name)
    if cls is None:
        raise SandboxError(f"unknown sandbox backend '{name}' (choose from: {', '.join(sorted(set(BACKENDS)))})")
    api_key = api_key or os.environ.get("MALYSIS_API_KEY")
    url = url or os.environ.get("MALYSIS_SANDBOX_URL")
    if cls is CAPE and not url:
        raise SandboxError("CAPE needs a sandbox URL (--sandbox-url or MALYSIS_SANDBOX_URL)")
    if cls in (Triage, VirusTotal) and not api_key:
        raise SandboxError(f"{name} needs an API key (--api-key or MALYSIS_API_KEY)")
    kwargs = dict(url=url, api_key=api_key, timeout=timeout, poll=poll, verify=not insecure)
    if cls is VirusTotal:
        kwargs["allow_upload"] = vt_upload
    return cls(**kwargs)


def findings_from_dynamic(result):
    """Turn sandbox output into the same finding shape static analysis produces."""
    findings = []
    score = result.get("score")
    if isinstance(score, (int, float)):
        if score >= 8 and result.get("backend") in ("cape", "triage"):
            findings.append({"severity": "high", "title": f"Sandbox score {score}/10",
                             "detail": "", "source": "dynamic"})
        elif result.get("backend") == "virustotal" and score >= 20:
            findings.append({"severity": "high", "title": f"VirusTotal detections {result.get('detections')}",
                             "detail": ", ".join(result.get("family", [])[:5]), "source": "dynamic"})
    for sig in (result.get("signatures") or [])[:60]:
        sev = sig.get("severity")
        level = "medium"
        if isinstance(sev, (int, float)):
            level = "high" if sev >= 7 else "medium" if sev >= 4 else "low"
        findings.append({"severity": level, "title": f"Sandbox signature: {sig.get('name')}",
                         "detail": sig.get("description") or "", "source": "dynamic"})
    net = result.get("network") or {}
    contacted = [d for d in (net.get("dns") or []) if d][:10]
    if contacted:
        findings.append({"severity": "medium", "title": "Domains contacted at runtime",
                         "detail": ", ".join(defang(d) for d in contacted), "source": "dynamic"})
    if result.get("family"):
        findings.append({"severity": "high", "title": "Malware family attribution",
                         "detail": ", ".join(result["family"][:5]), "source": "dynamic"})
    return findings
