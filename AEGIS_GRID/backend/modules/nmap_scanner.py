"""
Nmap Automation Module
Ported from: nmap_auto_full / Nmap_Auto_V2
Wraps nmap in a controlled subprocess call and parses results into JSON.
Requires nmap to be installed on the host running this backend, and
requires the caller to be authorized to scan the target.

Also supports a validated custom-command mode (dashboard "Command Library"
+ free-text box). Since this is invoked over a web API — including,
potentially, over a public tunnel — raw shell strings are never passed to
a shell; args are split with shlex and every token is checked against an
allowlist before nmap ever runs.

The allowlist covers the large majority of nmap's real flag surface:
scan types, timing/performance tuning, host discovery variants, version/OS
detection tuning, NSE scripts and arguments, port specs (including
attached forms like -p80,443), IPv6, verbosity/debugging. Two narrow
categories remain excluded, for two different reasons:
  1. Arbitrary file read/write (-oN/-oX/-oG/-oA/-iL/-iR, --resume, etc.) —
     this is a network-facing scanner; letting a request choose a
     filesystem path to write to (or read a target list from) is a real
     risk distinct from scan behavior. The tool already returns full XML
     results as JSON, so nothing is lost.
  2. Attribution evasion / third-party implication (-D decoy, -sI idle
     scan through a "zombie" host, --spoof-mac, -S source spoofing,
     -g/--source-port, -f fragmentation, -b FTP bounce) — these are about
     hiding who is scanning or routing traffic through/blaming an
     uninvolved host, not about scan aggressiveness. --script-args is
     allowed generally; only the literal unsafe=1/true toggle (which lets
     NSE scripts run checks that can crash the target service) is blocked.
"""
import re
import shlex
import shutil
import subprocess
import xml.etree.ElementTree as ET

# Flags allowed outright (no value, or value validated separately below).
ALLOWED_FLAGS = {
    # Scan types
    "-sV", "-sC", "-A", "-O", "-Pn", "-sS", "-sU", "-sT", "-sn",
    "-sA", "-sW", "-sM", "-sO", "-sY", "-sZ", "-F", "-p-",
    # Host discovery probe types (not spoofing — just probe method)
    "-PS", "-PA", "-PU", "-PY", "-PE", "-PP", "-PM", "--disable-arp-ping",
    # Port/target selection
    "-p", "--top-ports", "--exclude", "-n", "-R",
    # Timing templates + fine-grained timing control
    "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
    "--min-rate", "--max-retries", "--max-parallelism", "--min-parallelism",
    "--max-rtt-timeout", "--min-rtt-timeout", "--initial-rtt-timeout",
    "--host-timeout", "--scan-delay", "--max-scan-delay",
    "--defeat-rst-ratelimit", "--defeat-icmp-ratelimit",
    # Version/OS detection tuning
    "--version-intensity", "--version-light", "--version-all", "--version-trace",
    "--osscan-limit", "--osscan-guess", "--traceroute",
    # DNS
    "--dns-servers", "--system-dns",
    # NSE
    "--script", "--script-args", "--script-timeout",
    # Output/verbosity/debug (stdout only — no file paths)
    "-v", "-vv", "-d", "-dd", "--reason", "--open", "--packet-trace", "--stats-every",
    # IPv6
    "-6",
}

BLOCKED_FLAGS = {
    "-oN", "-oX", "-oG", "-oA", "-iL", "-iR", "-e", "-S", "-D", "-sI",
    "-g", "--source-port", "--resume", "--privileged", "--unprivileged",
    "--datadir", "--append-output", "--stylesheet", "-f", "-ff", "-b",
    "--spoof-mac", "--badsum",
}

# Value validators for flags that take one
NUMERIC_RE = re.compile(r"^[0-9,\-]+$")
TIME_VALUE_RE = re.compile(r"^\d+(\.\d+)?(ms|s|m|h)?$")
PORT_SPEC_RE = re.compile(r"^[0-9TU:,\-]+$")  # e.g. 80,443 or 1-1000 or U:53,T:80
SCRIPT_CATEGORY_RE = re.compile(r"^[a-zA-Z0-9_,\-]+$")  # no path chars
HOST_LIST_RE = re.compile(r"^[a-zA-Z0-9_.,:\-]+$")  # comma-separated hosts/IPs, no shell metachars

VALUE_VALIDATORS = {
    "-p": PORT_SPEC_RE,
    "--top-ports": NUMERIC_RE,
    "--min-rate": NUMERIC_RE,
    "--max-retries": NUMERIC_RE,
    "--max-parallelism": NUMERIC_RE,
    "--min-parallelism": NUMERIC_RE,
    "--version-intensity": NUMERIC_RE,
    "--max-rtt-timeout": TIME_VALUE_RE,
    "--min-rtt-timeout": TIME_VALUE_RE,
    "--initial-rtt-timeout": TIME_VALUE_RE,
    "--host-timeout": TIME_VALUE_RE,
    "--scan-delay": TIME_VALUE_RE,
    "--max-scan-delay": TIME_VALUE_RE,
    "--script-timeout": TIME_VALUE_RE,
    "--stats-every": TIME_VALUE_RE,
    "--dns-servers": HOST_LIST_RE,
    "--exclude": HOST_LIST_RE,
}

# -p also has an attached form: -p80,443 / -p1-1000 / -p- (already its own flag)
ATTACHED_PORT_RE = re.compile(r"^-p([0-9TU:,\-]+)$")
# Probe-type flags also support an attached port list: -PS80,443 / -PA22,80
ATTACHED_PROBE_RE = re.compile(r"^-P[SAUY]([0-9,\-]+)$")


def validate_custom_args(raw_args: str) -> dict:
    """Returns {'ok': True, 'tokens': [...]} or {'ok': False, 'error': ...}."""
    try:
        tokens = shlex.split(raw_args)
    except ValueError as e:
        return {"ok": False, "error": f"Could not parse command: {e}"}

    if not tokens:
        return {"ok": False, "error": "No flags provided."}

    i = 0
    while i < len(tokens):
        tok = tokens[i]

        if tok in BLOCKED_FLAGS:
            return {"ok": False, "error": f"Flag not permitted: {tok} (this specifically evades attribution, implicates a third party, or reads/writes arbitrary files — see the module docstring for why)"}

        # Attached port spec form: -p80,443
        if ATTACHED_PORT_RE.match(tok):
            i += 1
            continue

        # Attached probe port list: -PS80,443
        if ATTACHED_PROBE_RE.match(tok):
            i += 1
            continue

        if tok.startswith("-"):
            if tok not in ALLOWED_FLAGS:
                return {"ok": False, "error": f"Flag not on the allowlist: {tok}"}

            if tok == "--script":
                if i + 1 >= len(tokens) or not SCRIPT_CATEGORY_RE.match(tokens[i + 1]) or "/" in tokens[i + 1] or "." in tokens[i + 1]:
                    return {"ok": False, "error": "--script requires a plain category/script name, no paths"}
                i += 1
            elif tok == "--script-args":
                if i + 1 >= len(tokens):
                    return {"ok": False, "error": "--script-args requires a value"}
                val = tokens[i + 1]
                if "unsafe" in val.lower():
                    return {"ok": False, "error": "--script-args cannot include 'unsafe' — that toggle lets NSE scripts run checks that can crash the target service"}
                i += 1
            elif tok in VALUE_VALIDATORS:
                if i + 1 >= len(tokens) or not VALUE_VALIDATORS[tok].match(tokens[i + 1]):
                    return {"ok": False, "error": f"{tok} requires a valid value (got: {tokens[i+1] if i+1 < len(tokens) else 'nothing'})"}
                i += 1
            # else: bare flag, no value expected (e.g. -sV, -A, -v, -6...)
        else:
            return {"ok": False, "error": f"Unexpected bare token: {tok}"}
        i += 1

    return {"ok": True, "tokens": tokens}


def _nmap_available() -> bool:
    return shutil.which("nmap") is not None


def scan_target(target: str, profile: str = "default", timeout: int = 1800) -> dict:
    """
    Run an nmap scan against `target`.
    profile: "default" (-sV -T4), "full" (-p- -sV -sC), "quick" (-F)
    Only scan hosts/networks you are authorized to test.
    """
    if not _nmap_available():
        return {"error": "nmap is not installed on this host. Install it (e.g. apt install nmap) to enable scanning."}

    profiles = {
        "quick": ["-F", "-T4"],
        "default": ["-sV", "-T4"],
        "full": ["-p-", "-sV", "-sC", "-T4"],
    }
    args = ["nmap", "-oX", "-"] + profiles.get(profile, profiles["default"]) + [target]
    return _run_nmap(args, target, timeout)


def scan_target_custom(target: str, raw_args: str, timeout: int = 1800) -> dict:
    """Runs a validated, user-supplied set of nmap flags against `target`."""
    if not _nmap_available():
        return {"error": "nmap is not installed on this host. Install it (e.g. apt install nmap) to enable scanning."}

    validation = validate_custom_args(raw_args)
    if not validation["ok"]:
        return {"error": validation["error"]}

    args = ["nmap", "-oX", "-"] + validation["tokens"] + [target]
    return _run_nmap(args, target, timeout)


def _run_nmap(args: list, target: str, timeout: int) -> dict:
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {
            "error": (
                f"Scan exceeded the {timeout}s backstop and was stopped. This is a generous safety "
                "net (30 min), not a scan-size limit — for anything longer, use the async job endpoint "
                "(Security Sessions → Nmap → Run Scan), which has no timeout at all."
            )
        }

    if proc.returncode != 0:
        return {"error": proc.stderr.strip() or "nmap exited with a non-zero status"}

    return _parse_nmap_xml(proc.stdout, target)


def _parse_nmap_xml(xml_output: str, target: str) -> dict:
    """
    Parses nmap's XML output. Critically, this surfaces WHY a host shows
    zero ports instead of just returning an empty list, which previously
    made three completely different situations look identical:
      1. Host is up, scanned N ports, ALL of them closed/filtered — nmap
         summarizes this as <extraports state="closed" count="N"/> with NO
         individual <port> elements at all (confirmed directly against a
         known-open host — even 127.0.0.1 with a real listener produces
         this shape if the scanned range doesn't include an open port).
      2. Host never responded to discovery and was skipped — no <ports>
         element at all, status state="down".
      3. Scan timed out mid-host — host has timedout="true", no <ports>.
    All three used to render as identical empty {"ports": []}, which is
    indistinguishable from "the tool didn't work." Now they aren't.
    """
    result = {"target": target, "hosts": [], "scan_summary": None}
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as e:
        return {"error": f"Failed to parse nmap output: {e}"}

    runstats = root.find("runstats")
    if runstats is not None:
        finished = runstats.find("finished")
        hosts_stat = runstats.find("hosts")
        if finished is not None or hosts_stat is not None:
            result["scan_summary"] = {
                "summary": finished.get("summary") if finished is not None else None,
                "elapsed_seconds": finished.get("elapsed") if finished is not None else None,
                "hosts_up": hosts_stat.get("up") if hosts_stat is not None else None,
                "hosts_down": hosts_stat.get("down") if hosts_stat is not None else None,
            }

    for host in root.findall("host"):
        addr_el = host.find("address")
        addr = addr_el.get("addr") if addr_el is not None else "unknown"
        status_el = host.find("status")

        host_entry = {
            "address": addr,
            "status": status_el.get("state") if status_el is not None else "unknown",
            "status_reason": status_el.get("reason") if status_el is not None else None,
            "timed_out": host.get("timedout") == "true",
            "ports": [],
            "closed_or_filtered_summary": [],
        }

        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                state = port.find("state")
                service = port.find("service")
                port_entry = {
                    "port": port.get("portid"),
                    "protocol": port.get("protocol"),
                    "state": state.get("state") if state is not None else "unknown",
                    "service": service.get("name") if service is not None else "unknown",
                    "product": service.get("product") if service is not None else None,
                    "version": service.get("version") if service is not None else None,
                    "scripts": [],
                }
                # NSE script output (vuln, banner, auth, anything run with
                # --script) was previously discarded entirely — this is
                # what a "vuln scan" is actually FOR, and it was silently
                # dropped, which is exactly what made --script vuln look
                # like it wasn't doing anything.
                for script in port.findall("script"):
                    port_entry["scripts"].append({"id": script.get("id"), "output": script.get("output")})
                host_entry["ports"].append(port_entry)
            # Ports nmap doesn't list individually because they're ALL in
            # the same state get summarized here instead — this is the
            # part that was previously silently dropped.
            for extraports in ports_el.findall("extraports"):
                host_entry["closed_or_filtered_summary"].append(
                    {"state": extraports.get("state"), "count": extraports.get("count")}
                )

        # Host-level scripts (as opposed to per-port) — e.g. some
        # discovery/broadcast scripts report at the host level, not
        # attached to any specific port.
        hostscript_el = host.find("hostscript")
        if hostscript_el is not None:
            host_entry["host_scripts"] = [
                {"id": s.get("id"), "output": s.get("output")} for s in hostscript_el.findall("script")
            ]

        result["hosts"].append(host_entry)

    return result


# Public alias — used by core/job_manager.py for the async job path.
parse_nmap_xml = _parse_nmap_xml
