"""
Job Manager
Runs long-running scans (nmap, primarily) as background jobs instead of
blocking an HTTP request for however long the scan takes. No default
timeout — a scan runs until it finishes or the caller explicitly cancels
it, since the old fixed 300s cutoff was cutting off legitimate full-port
and vuln-script scans on slower targets.

Progress is parsed from nmap's own --stats-every output (injected
automatically) so the dashboard can show real percentage-complete, not
just a spinner.
"""
import re
import subprocess
import threading
import time
import uuid

_JOBS = {}
_LOCK = threading.Lock()
_PROGRESS_RE = re.compile(r"(\d+\.\d+)%\s+done")


def _new_job(target: str, command_desc: str) -> str:
    job_id = uuid.uuid4().hex[:12]
    with _LOCK:
        _JOBS[job_id] = {
            "id": job_id,
            "target": target,
            "command": command_desc,
            "status": "running",  # running | done | failed | cancelled
            "progress": None,  # float 0-100, or None if unknown yet
            "started_at": time.time(),
            "finished_at": None,
            "result": None,
            "error": None,
            "log_tail": [],
            "history_saved": False,
            "_proc": None,
        }
    return job_id


def mark_history_saved(job_id: str) -> None:
    with _LOCK:
        job = _JOBS.get(job_id)
        if job:
            job["history_saved"] = True


def get_job(job_id: str) -> dict:
    with _LOCK:
        job = _JOBS.get(job_id)
        if not job:
            return None
        # never expose the raw Popen handle to callers
        return {k: v for k, v in job.items() if k != "_proc"}


def list_jobs() -> list:
    with _LOCK:
        return [{k: v for k, v in j.items() if k != "_proc"} for j in _JOBS.values()]


def cancel_job(job_id: str) -> bool:
    with _LOCK:
        job = _JOBS.get(job_id)
        if not job or job["status"] != "running":
            return False
        proc = job.get("_proc")
        if proc:
            proc.terminate()
        job["status"] = "cancelled"
        job["finished_at"] = time.time()
    return True


def start_nmap_job(target: str, args: list, command_desc: str, parse_fn) -> str:
    """
    args: validated nmap flag list (NOT including 'nmap', '-oX -', or target)
    parse_fn: function(xml_text, target) -> dict, reused from nmap_scanner
    """
    job_id = _new_job(target, command_desc)

    # Inject -v and --stats-every so progress lines actually get emitted,
    # unless the caller already specified their own stats interval.
    full_args = ["nmap"] + args
    if not any(a.startswith("--stats-every") for a in args):
        full_args += ["--stats-every", "2s"]
    if "-v" not in args and "-vv" not in args:
        full_args += ["-v"]
    full_args += ["-oX", "-", target]

    def run():
        try:
            proc = subprocess.Popen(full_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            with _LOCK:
                _JOBS[job_id]["_proc"] = proc

            xml_lines = []
            for line in proc.stdout:
                match = _PROGRESS_RE.search(line)
                with _LOCK:
                    job = _JOBS.get(job_id)
                    if not job:
                        return
                    if match:
                        job["progress"] = float(match.group(1))
                    job["log_tail"].append(line.rstrip())
                    job["log_tail"] = job["log_tail"][-40:]  # keep it bounded
                # nmap's XML output is interleaved with human stats lines on
                # stdout when -v is used; XML tags start with '<'
                if line.lstrip().startswith("<"):
                    xml_lines.append(line)

            proc.wait()
            with _LOCK:
                job = _JOBS.get(job_id)
                if not job or job["status"] == "cancelled":
                    return
                if proc.returncode != 0:
                    job["status"] = "failed"
                    job["error"] = "nmap exited with a non-zero status. See log_tail for details."
                else:
                    result = parse_fn("".join(xml_lines), target)
                    job["status"] = "failed" if "error" in result else "done"
                    job["result"] = result
                    job["error"] = result.get("error")
                job["progress"] = 100 if job["status"] == "done" else job["progress"]
                job["finished_at"] = time.time()
        except Exception as e:
            with _LOCK:
                job = _JOBS.get(job_id)
                if job:
                    job["status"] = "failed"
                    job["error"] = f"Job crashed: {str(e)[:300]}"
                    job["finished_at"] = time.time()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return job_id
