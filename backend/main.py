import asyncio
import ipaddress
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import uuid
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

app = FastAPI(
    title="theHarvester Browser UI API",
    description="Full-stack browser interface backend for running theHarvester OSINT reconnaissance tool locally.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Supported engines from Core.get_supportedengines() in theHarvester + common fallbacks
SUPPORTED_SOURCES = [
    'baidu',
    'bevigil',
    'bitbucket',
    'bufferoverun',
    'builtwith',
    'brave',
    'censys',
    'certspotter',
    'chaos',
    'commoncrawl',
    'criminalip',
    'crtsh',
    'dehashed',
    'dnsdumpster',
    'duckduckgo',
    'dymo',
    'fofa',
    'fullhunt',
    'github-code',
    'gitlab',
    'hackertarget',
    'haveibeenpwned',
    'hudsonrock',
    'hunter',
    'hunterhow',
    'intelx',
    'leakix',
    'leaklookup',
    'linkedin',
    'linkedin_links',
    'mojeek',
    'netcraft',
    'netlas',
    'omnisint',
    'onyphe',
    'otx',
    'pentesttools',
    'projectdiscovery',
    'rapiddns',
    'robtex',
    'rocketreach',
    'securityscorecard',
    'securityTrails',
    'sherlockeye',
    'shodan',
    'shodanInternetDB',
    'subdomaincenter',
    'subdomainfinderc99',
    'sublist3r',
    'thc',
    'threatcrowd',
    'tomba',
    'urlscan',
    'venacus',
    'virustotal',
    'waybackarchive',
    'whoisxml',
    'windvane',
    'yahoo',
    'zoomeye',
    'zoomeyeapi',
    'anubis',
    'bing',
    'threatminer'
]

WHITELISTED_SOURCES = set(SUPPORTED_SOURCES + ["all"])

# In-memory storage for jobs and active WebSocket subscribers
jobs: Dict[str, Dict[str, Any]] = {}
job_subscribers: Dict[str, List[WebSocket]] = {}

SUBPROCESS_TIMEOUT_SECONDS = 900  # 15 minutes maximum runtime for a passive collection job


class ScanRequest(BaseModel):
    domain: str
    sources: List[str]
    limit: int = Field(default=500, ge=1, le=5000)
    dns_brute: bool = Field(default=False)


class ShodanAssetRequest(BaseModel):
    asset: str = Field(min_length=1, max_length=253)
    authorized: bool = Field(default=False)
    limit: int = Field(default=100, ge=1, le=1000)


def validate_shodan_asset(asset: str, authorized: bool) -> dict[str, Any]:
    candidate = asset.strip().lower().rstrip('.')
    if not authorized:
        raise HTTPException(status_code=403, detail='Explicit authorization is required before a Shodan asset review.')
    try:
        parsed_ip = ipaddress.ip_address(candidate)
        normalized = str(parsed_ip)
        kind = 'ip'
        private = parsed_ip.is_private
    except ValueError:
        if not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', candidate):
            raise HTTPException(status_code=422, detail='Asset must be a valid domain name or IP address.')
        normalized = candidate
        kind = 'domain'
        private = False
    return {
        'asset': normalized,
        'kind': kind,
        'authorized': True,
        'private_or_lab_target': private,
        'scope': 'passive Shodan metadata only',
        'allowed_evidence': ['hostnames', 'ports', 'service banners', 'products', 'organization', 'ASN'],
        'excluded_actions': ['camera-feed access', 'authentication attempts', 'exploit execution', 'active port scanning'],
    }


@app.post('/api/modules/shodan-assets/validate')
def validate_shodan_asset_request(request: ShodanAssetRequest):
    result = validate_shodan_asset(request.asset, request.authorized)
    return {**result, 'limit': request.limit, 'next_step': 'Use the Domain OSINT workflow with the shodan source to start a passive review.'}


@app.get('/api/health')
def health_check():
    return {"status": "healthy", "service": "theHarvester Browser UI API"}


@app.get("/api/diagnostics")
def diagnostics():
    """Return non-sensitive runtime details useful for reproducing setup failures."""
    yaml_candidates = [
        os.path.expanduser('~/.theHarvester/api-keys.yaml'),
        '/etc/theHarvester/api-keys.yaml',
        os.path.join(os.path.dirname(__file__), '..', 'theHarvester', 'data', 'api-keys.yaml'),
    ]
    yaml_configured = False
    for candidate in yaml_candidates:
        try:
            with open(candidate, encoding='utf-8') as config_file:
                content = config_file.read()
            if "shodan:" in content and "key: ''" not in content:
                yaml_configured = True
                break
        except OSError:
            continue
    return {
        'python': sys.version.split()[0],
        'theharvester_executable': shutil.which('theHarvester') or shutil.which('theHarvester.exe') or shutil.which('theHarvester.py'),
        'shodan_key_configured': bool(os.getenv('SHODAN_API_KEY', '').strip()) or yaml_configured,
        'shodan_key_source': 'environment' if os.getenv('SHODAN_API_KEY', '').strip() else ('yaml' if yaml_configured else None),
        'safe_scope': 'passive metadata for authorized assets only',
    }


@app.get("/api/sources")
def get_sources():
    """Returns whitelisted sources and recommended defaults for the UI."""
    return {
        "sources": sorted(list(set(SUPPORTED_SOURCES))),
        "recommended": [
            "crtsh",
            "dnsdumpster",
            "duckduckgo",
            "hackertarget",
            "otx",
            "urlscan",
            "rapiddns",
            "bevigil",
            "brave"
        ]
    }


@app.get("/api/jobs")
def list_jobs():
    """List recent scan jobs stored in memory."""
    job_list = []
    for jid, job in sorted(jobs.items(), key=lambda x: x[1]["created_at"], reverse=True):
        job_list.append({
            "job_id": job["job_id"],
            "domain": job["domain"],
            "sources": job["sources"],
            "limit": job["limit"],
            "dns_brute": job["dns_brute"],
            "status": job["status"],
            "command_str": job["command_str"],
            "exit_code": job["exit_code"],
            "created_at": job["created_at"],
            "finished_at": job["finished_at"],
        })
    return {"jobs": job_list[:50]}


async def broadcast_event(job_id: str, payload: dict):
    """Send an event payload to all active WebSocket clients monitoring job_id."""
    if job_id not in job_subscribers:
        return
    to_remove = []
    for ws in job_subscribers[job_id]:
        try:
            await ws.send_json(payload)
        except Exception:
            to_remove.append(ws)
    for ws in to_remove:
        if ws in job_subscribers[job_id]:
            job_subscribers[job_id].remove(ws)


async def execute_job(job_id: str):
    """Background task to run theHarvester process and stream logs."""
    job = jobs.get(job_id)
    if not job:
        return

    job["status"] = "Running"
    await broadcast_event(job_id, {"type": "status", "status": "Running"})
    await broadcast_event(job_id, {"type": "command", "data": job["command_str"]})

    cmd = job["command"]

    is_popen = False
    try:
        # Run process asynchronously with shell=False (security guarantee)
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
    except (NotImplementedError, RuntimeError, OSError):
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False
            )
            is_popen = True
        except Exception as popen_e:
            job["status"] = "Error"
            job["exit_code"] = -1
            job["finished_at"] = time.time()
            job["error_message"] = f"Failed to start theHarvester process: {repr(popen_e)} ({type(popen_e).__name__})"
            err_msg = f"[ERROR] {job['error_message']}"
            job["output_lines"].append(err_msg)
            await broadcast_event(job_id, {"type": "output", "data": err_msg})
            await broadcast_event(job_id, {
                "type": "done",
                "status": job["status"],
                "exit_code": job["exit_code"],
                "error_message": job["error_message"],
            })
            return
    except FileNotFoundError:
        job["status"] = "Error"
        job["exit_code"] = -1
        job["finished_at"] = time.time()
        job["error_message"] = "theHarvester executable not found in system PATH or python environment."
        err_msg = "[ERROR] theHarvester executable not found in system PATH. Please install theHarvester or verify your environment."
        job["output_lines"].append(err_msg)
        await broadcast_event(job_id, {"type": "output", "data": err_msg})
        await broadcast_event(job_id, {
            "type": "done",
            "status": job["status"],
            "exit_code": job["exit_code"],
            "error_message": job["error_message"],
        })
        return
    except Exception as e:
        job["status"] = "Error"
        job["exit_code"] = -1
        job["finished_at"] = time.time()
        job["error_message"] = f"Failed to start theHarvester process: {repr(e)} ({type(e).__name__})"
        err_msg = f"[ERROR] {job['error_message']}"
        job["output_lines"].append(err_msg)
        await broadcast_event(job_id, {"type": "output", "data": err_msg})
        await broadcast_event(job_id, {
            "type": "done",
            "status": job["status"],
            "exit_code": job["exit_code"],
            "error_message": job["error_message"],
        })
        return

    async def read_stream(stream, is_stderr=False):
        while True:
            if hasattr(stream, "readline") and asyncio.iscoroutinefunction(stream.readline):
                line_bytes = await stream.readline()
            else:
                line_bytes = await asyncio.to_thread(stream.readline)
            if not line_bytes:
                break
            line_str = line_bytes.decode("utf-8", errors="replace").rstrip("\r\n")
            if is_stderr and not line_str.startswith("[STDERR]"):
                line_str = f"[STDERR] {line_str}"
            job["output_lines"].append(line_str)
            await broadcast_event(job_id, {"type": "output", "data": line_str})

    try:
        async with asyncio.timeout(SUBPROCESS_TIMEOUT_SECONDS):
            await asyncio.gather(
                read_stream(process.stdout, False),
                read_stream(process.stderr, True)
            )
            if is_popen:
                exit_code = await asyncio.to_thread(process.wait)
            else:
                exit_code = await process.wait()
            job["exit_code"] = exit_code
            job["finished_at"] = time.time()
            if exit_code == 0:
                job["status"] = "Finished"
            else:
                job["status"] = "Error"
                job["error_message"] = f"Process exited with non-zero exit code {exit_code}."
    except TimeoutError:
        try:
            process.kill()
            if is_popen:
                await asyncio.to_thread(process.wait)
            else:
                await process.wait()
        except Exception:
            pass
        job["status"] = "Error"
        job["exit_code"] = -9
        job["finished_at"] = time.time()
        job["error_message"] = f"Scan exceeded {SUBPROCESS_TIMEOUT_SECONDS}s timeout and was terminated."
        timeout_line = f"\n[ERROR] Execution timed out after {SUBPROCESS_TIMEOUT_SECONDS} seconds. Process terminated."
        job["output_lines"].append(timeout_line)
        await broadcast_event(job_id, {"type": "output", "data": timeout_line})

    await broadcast_event(job_id, {
        "type": "done",
        "status": job["status"],
        "exit_code": job["exit_code"],
        "error_message": job["error_message"],
    })


@app.post("/api/scan")
async def start_scan(request: Request):
    """
    POST /api/scan
    Accepts form data or JSON payload, validates strictly, constructs command list (shell=False),
    starts background process, and returns job_id.
    """
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON format.")
        domain = body.get("domain", "")
        sources = body.get("sources", [])
        limit = body.get("limit", 500)
        dns_brute = body.get("dns_brute", False)
    else:
        form = await request.form()
        domain = form.get("domain", "")
        sources = form.getlist("sources")
        if not sources and "sources" in form:
            val = form.get("sources", "")
            if isinstance(val, str) and "," in val:
                sources = [s.strip() for s in val.split(",") if s.strip()]
            elif val:
                sources = [val]
        try:
            limit = int(form.get("limit", 500))
        except ValueError:
            raise HTTPException(status_code=400, detail="Limit must be an integer between 1 and 5000.")
        dns_brute_val = form.get("dns_brute", False)
        dns_brute = dns_brute_val in (True, "true", "True", "1", 1, "on", "yes")

    # Strict domain validation: reject spaces, semicolons, quotes, pipes, backticks, etc.
    domain = str(domain).strip().lower()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain field is required.")
    
    if not re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain) or any(c in domain for c in ' \t\r\n;|`$()&\'"<>\\/[]{}!@#%^*+=?'):
        raise HTTPException(
            status_code=400,
            detail="Invalid domain format. Only letters, digits, hyphens, and periods are allowed (e.g. example.com)."
        )

    # Whitelist source validation
    if not isinstance(sources, list) or len(sources) == 0:
        raise HTTPException(status_code=400, detail="At least one data source must be selected.")

    cleaned_sources = [str(s).strip() for s in sources if str(s).strip()]
    invalid_sources = [s for s in cleaned_sources if s not in WHITELISTED_SOURCES]
    if invalid_sources:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid or unsupported source(s): {', '.join(invalid_sources)}. Allowed values must match whitelisted theHarvester sources."
        )

    # Validate limit
    try:
        limit = int(limit)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Limit must be a valid integer.")
    if limit < 1 or limit > 5000:
        raise HTTPException(status_code=400, detail="Limit must be between 1 and 5000.")

    dns_brute = bool(dns_brute)

    # Construct theHarvester command as a Python list (NEVER a shell string)
    theharvester_bin = shutil.which("theHarvester") or shutil.which("theHarvester.exe") or shutil.which("theHarvester.py")
    if theharvester_bin:
        cmd = [theharvester_bin]
    else:
        # Fallback to current python interpreter running `-m theHarvester`
        cmd = [sys.executable, "-m", "theHarvester"]

    cmd.extend(["-d", domain])

    if "all" in cleaned_sources:
        cmd.extend(["-b", "all"])
    else:
        cmd.extend(["-b", ",".join(sorted(set(cleaned_sources)))])

    cmd.extend(["-l", str(limit)])

    if dns_brute:
        cmd.append("-c")

    # Human-readable command display string
    # Always present cleanly starting with "theHarvester"
    if "-d" in cmd:
        human_readable_cmd = "theHarvester " + " ".join(cmd[cmd.index("-d"):])
    else:
        human_readable_cmd = " ".join(cmd)

    job_id = str(uuid.uuid4())
    jobs[job_id] = {
        "job_id": job_id,
        "domain": domain,
        "sources": cleaned_sources,
        "limit": limit,
        "dns_brute": dns_brute,
        "status": "Queued",
        "command": cmd,
        "command_str": human_readable_cmd,
        "output_lines": [],
        "exit_code": None,
        "error_message": None,
        "created_at": time.time(),
        "finished_at": None,
    }
    job_subscribers[job_id] = []

    # Launch background job
    asyncio.create_task(execute_job(job_id))

    return {
        "job_id": job_id,
        "status": "Queued",
        "command_str": human_readable_cmd,
        "domain": domain,
        "sources": cleaned_sources,
        "limit": limit,
        "dns_brute": dns_brute
    }


@app.websocket("/api/scan/{job_id}/stream")
async def websocket_scan_stream(websocket: WebSocket, job_id: str):
    """
    WS /api/scan/{job_id}/stream
    Streams: (a) constructed command string first, then (b) live output lines,
    then (c) final 'done' message with status and exit code.
    """
    await websocket.accept()
    job = jobs.get(job_id)
    if not job:
        await websocket.send_json({"type": "error", "message": f"Job ID {job_id} not found."})
        await websocket.close()
        return

    if job_id not in job_subscribers:
        job_subscribers[job_id] = []
    job_subscribers[job_id].append(websocket)

    try:
        # (a) Send the constructed command string first
        await websocket.send_json({"type": "command", "data": job["command_str"]})
        # Send initial status
        await websocket.send_json({"type": "status", "status": job["status"]})

        # (b) Replay all output lines accumulated so far so late subscribers never miss lines
        for line in job["output_lines"]:
            await websocket.send_json({"type": "output", "data": line})

        # (c) If job is already done when connected, send done message immediately
        if job["status"] in ("Finished", "Error"):
            await websocket.send_json({
                "type": "done",
                "status": job["status"],
                "exit_code": job["exit_code"],
                "error_message": job["error_message"],
            })

        # Keep WebSocket alive to listen for ongoing live stream events
        while True:
            msg = await websocket.receive_text()
            if msg == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        if job_id in job_subscribers and websocket in job_subscribers[job_id]:
            job_subscribers[job_id].remove(websocket)


@app.get("/api/scan/{job_id}/result")
async def get_scan_result(job_id: str):
    """
    GET /api/scan/{job_id}/result
    Returns the full stored output and metadata for a completed or active job.
    """
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found.")
    
    return {
        "job_id": job["job_id"],
        "domain": job["domain"],
        "sources": job["sources"],
        "limit": job["limit"],
        "dns_brute": job["dns_brute"],
        "status": job["status"],
        "command_str": job["command_str"],
        "output_lines": job["output_lines"],
        "output_text": "\n".join(job["output_lines"]),
        "exit_code": job["exit_code"],
        "error_message": job["error_message"],
        "created_at": job["created_at"],
        "finished_at": job["finished_at"],
    }


@app.get("/api/scan/{job_id}/download")
async def download_scan_result(job_id: str):
    """Download full final output as a .txt file."""
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found.")

    output_text = f"===========================================================\n"
    output_text += f" theHarvester OSINT Reconnaissance Report\n"
    output_text += f"===========================================================\n"
    output_text += f"Job ID      : {job['job_id']}\n"
    output_text += f"Domain      : {job['domain']}\n"
    output_text += f"Command     : {job['command_str']}\n"
    output_text += f"Status      : {job['status']}\n"
    if job['exit_code'] is not None:
        output_text += f"Exit Code   : {job['exit_code']}\n"
    output_text += f"Date        : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(job['created_at']))}\n"
    output_text += f"===========================================================\n\n"
    output_text += "\n".join(job["output_lines"])

    filename = f"theHarvester_{job['domain']}_{job_id[:8]}.txt"
    return PlainTextResponse(
        content=output_text,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


# Strix-inspired safe assessment views. These expose evidence and remediation metadata
# from existing passive jobs; they never execute exploits or active target scans.
def _run_or_404(run_id: str) -> Dict[str, Any]:
    run = jobs.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail='Assessment run not found.')
    return run


def _extract_result_lines(lines: List[str], kind: str) -> List[str]:
    aliases = {'emails': r'emails?', 'hosts': r'hosts?', 'ips': r'ips?|ip addresses?', 'urls': r'urls?', 'people': r'people'}
    heading = re.compile(rf'\b({aliases[kind]})\s+(?:found|discovered|available)\b', re.I)
    section = None
    values: List[str] = []
    for raw in lines:
        line = re.sub(r'\x1b\[[0-9;]*m', '', str(raw or '')).strip()
        if not line or line.startswith('[CONNECTION]'):
            continue
        if heading.search(line):
            section = kind
            continue
        if re.match(r'^(?:\[.*?\]|read\s|={3,}|[-*]{3,}|target\s*:|searching\b|failed\s+to|error\s+message|exception\s+occurred|no\s+.+\s+found|coded\s+by\b|christian\s+martorella\b|.*edge-security\.com\b)', line, re.I):
            section = None
            continue
        if section == kind:
            values.append(re.sub(r'^[-*•]\s*', '', line).strip())
    return values


def _extract_run_entities(lines: List[str]) -> Dict[str, List[str]]:
    unique = lambda values: sorted(set(values), key=str.casefold)
    diagnostic_lines = [line for line in lines if not re.match(r'^(?:\[.*?\]|read\s|searching\b|no\s+|target\s*:|failed\s+to|error\s+message|exception\s+occurred|coded\s+by\b|christian\s+martorella\b)', str(line).strip(), re.I) and not re.search(r'not\s+in\s+shodan|edge-security\.com', str(line), re.I)]
    emails = unique(re.findall(r'[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}', '\n'.join(diagnostic_lines), re.I))
    emails = [email for email in emails if not re.search(r'edge-security\.com$', email, re.I)]
    ips = unique(re.findall(r'\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b', '\n'.join(diagnostic_lines)))
    urls = unique([url.rstrip('),.;') for url in re.findall(r'https?://[^\s<>"\']+', '\n'.join(diagnostic_lines), re.I)])
    hosts = [host for host in unique(re.findall(r'\b(?=[a-z0-9.-]{4,253}\b)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b', '\n'.join(_extract_result_lines(lines, 'hosts')), re.I)) if not re.search(r'\.(?:ya?ml|txt|log)$', host, re.I)]
    people = unique([line for line in _extract_result_lines(lines, 'people') if re.fullmatch(r'[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3}', line)])
    services = unique([match.strip() for line in lines if not re.match(r'^(?:\[.*?\]|read\s|searching\b|no\s+|target\s*:)', str(line).strip(), re.I) for match in re.findall(r'\b(?:port\s*\d{1,5}|https?|ssh|ftp|smtp|dns|rdp|mysql|postgres(?:ql)?|mongodb|redis|telnet)\b[^\n]*', str(line), re.I) if len(match.strip()) < 120])
    return {'emails': emails, 'hosts': hosts, 'ips': ips, 'urls': urls, 'people': people, 'services': services}


def _derive_run_findings(lines: List[str]) -> List[Dict[str, str]]:
    text = '\n'.join(lines)
    findings: List[Dict[str, str]] = []
    if re.search(r'missing api key', text, re.I):
        findings.append({'id': 'provider-credentials', 'severity': 'medium', 'title': 'Provider credentials are incomplete', 'evidence': 'A configured passive provider reported a missing API key.', 'remediation': 'Configure only the provider credentials required for the authorized assessment.'})
    if re.search(r'invalid response format|work item.*error|exception occurred|traceback', text, re.I):
        findings.append({'id': 'provider-diagnostic', 'severity': 'low', 'title': 'Provider returned an unexpected response', 'evidence': 'The captured output contains a provider or parser diagnostic.', 'remediation': 'Review the provider output, update dependencies, or disable that provider for the run.'})
    if re.search(r'websocket.*unavailable|unsupported upgrade request|live stream unavailable', text, re.I):
        findings.append({'id': 'stream-fallback', 'severity': 'low', 'title': 'Live stream transport was unavailable', 'evidence': 'The client used the REST result fallback to retrieve the run output.', 'remediation': 'Install the WebSocket dependency in the active virtual environment.'})
    if re.search(r'no (?:ips|hosts|emails) found', text, re.I):
        findings.append({'id': 'empty-result', 'severity': 'info', 'title': 'No matching entities were returned', 'evidence': 'TheHarvester reported an empty result for one or more entity types.', 'remediation': 'Compare additional authorized passive sources and review provider coverage.'})
    return findings


def _run_summary(run: Dict[str, Any]) -> Dict[str, Any]:
    findings = _derive_run_findings(run['output_lines'])
    severity_counts = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for finding in findings:
        severity_counts[finding['severity']] += 1
    entities = _extract_run_entities(run['output_lines'])
    return {
        'run_id': run['job_id'],
        'name': f"{run['domain']}-{run['job_id'][:8]}",
        'target': run['domain'],
        'status': run['status'].lower(),
        'authorized_scope': 'passive metadata for authorized assets only',
        'severity_counts': severity_counts,
        'finding_count': len(findings),
        'entity_counts': {key: len(value) for key, value in entities.items()},
        'output_line_count': len(run['output_lines']),
        'created_at': run['created_at'],
        'finished_at': run['finished_at'],
    }


@app.get('/api/runs')
def list_assessment_runs():
    """Strix-inspired run index backed by the existing in-memory passive jobs."""
    return {'runs': [_run_summary(run) for run in sorted(jobs.values(), key=lambda item: item['created_at'], reverse=True)[:50]]}


@app.get('/api/runs/{run_id}')
def get_assessment_run(run_id: str):
    run = _run_or_404(run_id)
    return {**_run_summary(run), 'command': run['command_str'], 'sources': run['sources'], 'limit': run['limit'], 'dns_brute': run['dns_brute']}


@app.get('/api/runs/{run_id}/summary')
def get_assessment_summary(run_id: str):
    return _run_summary(_run_or_404(run_id))


@app.get('/api/runs/{run_id}/evidence')
def get_assessment_evidence(run_id: str):
    run = _run_or_404(run_id)
    return {'run_id': run_id, 'target': run['domain'], 'entities': _extract_run_entities(run['output_lines']), 'output_lines': run['output_lines']}


@app.get('/api/runs/{run_id}/findings')
def get_assessment_findings(run_id: str):
    run = _run_or_404(run_id)
    findings = _derive_run_findings(run['output_lines'])
    return {'run_id': run_id, 'findings': findings, 'severity_counts': _run_summary(run)['severity_counts']}


@app.get('/api/runs/{run_id}/report')
def get_assessment_report(run_id: str):
    run = _run_or_404(run_id)
    return {'run': _run_summary(run), 'findings': _derive_run_findings(run['output_lines']), 'evidence': _extract_run_entities(run['output_lines']), 'artifacts': {'text_report': f'/api/scan/{run_id}/download'}}
