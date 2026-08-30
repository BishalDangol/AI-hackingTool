# AI Hacking Tool: User and Operator Guide

## 1. Purpose and scope

This project is a local web application for **passive OSINT and authorized security assessment**. It provides a browser interface around theHarvester and related passive data sources, then organizes the captured output into entities, evidence, findings, charts, and reports.

> Use the application only against domains, IP addresses, repositories, and devices that you own or are explicitly authorized to assess. The application does not provide unauthorized camera-feed access, authentication bypass, exploit execution, credential attacks, persistence, or post-exploitation.

The application has two local processes. The **FastAPI backend** validates requests, starts theHarvester safely without a shell, captures stdout and stderr, stores jobs in memory, and exposes REST/WebSocket endpoints. The **React/Vite frontend** provides the browser workspace, submits scans, displays live output, falls back to REST polling when WebSockets are unavailable, and renders structured results.

| Process | Default address | Responsibility |
|---|---|---|
| FastAPI backend | `http://127.0.0.1:8000` | Scan execution, job state, output capture, diagnostics, reports, and structured API responses. |
| React/Vite frontend | `http://localhost:5173` | Configuration screens, live terminal, charts, findings, history, and report controls. |

## 2. Windows installation with Git Bash

Open Git Bash and clone the repository:

```bash
git clone https://github.com/BishalDangol/AI-hackingTool.git
cd AI-hackingTool
```

Create a Python virtual environment. The project currently uses Python 3.12 in its tested environment:

```bash
py -3.12 -m venv .venv
source .venv/Scripts/activate
```

If `source` does not activate the environment, use the Windows path directly:

```bash
.venv/Scripts/activate
```

Install or update the backend dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -e .
```

The live stream requires a WebSocket implementation. The project declares this dependency, but installing it explicitly is useful when repairing an older local environment:

```bash
python -m pip install websockets==15.0.1
```

Verify the active environment:

```bash
which python
python --version
python -c "import fastapi, uvicorn, websockets; print('backend dependencies: ok')"
```

## 3. Configure Shodan safely

Set the Shodan key only in the current Git Bash session. Never commit it, add it to a screenshot, or paste it into a bug report:

```bash
export SHODAN_API_KEY='your-new-shodan-api-key'
```

Confirm only that the variable exists without printing its value:

```bash
if [ -n "$SHODAN_API_KEY" ]; then echo 'SHODAN_API_KEY is configured'; else echo 'SHODAN_API_KEY is missing'; fi
```

TheHarvester’s YAML fallback is also supported at:

```text
~/.theHarvester/api-keys.yaml
```

Example local-only YAML:

```yaml
apikeys:
  shodan:
    key: 'your-new-shodan-api-key'
```

The repository contains an empty configuration template. Keep populated configuration files outside Git.

## 4. Start the application normally

### 4.1 Start the backend

In the first Git Bash window, from the repository root:

```bash
cd /e/path/to/AI-hackingTool
source .venv/Scripts/activate
export SHODAN_API_KEY='your-new-shodan-api-key'
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

Leave this terminal open. It displays backend startup messages and process errors.

Check the backend from a second terminal:

```bash
curl -sS http://127.0.0.1:8000/api/health
curl -sS http://127.0.0.1:8000/api/diagnostics
```

The diagnostics response is credential-safe. It reports whether a Shodan key is configured, but never returns the key.

### 4.2 Start the frontend

In a second Git Bash window:

```bash
cd /e/path/to/AI-hackingTool/frontend
npm install
npm run dev
```

Open the Vite URL shown in the terminal, normally:

```text
http://localhost:5173
```

The frontend expects the backend at `http://127.0.0.1:8000`. Start both processes before launching a scan.

## 5. How a scan works

The normal scan lifecycle is:

```text
Enter authorized domain
        ↓
Select passive sources and options
        ↓
Frontend sends POST /api/scan
        ↓
Backend validates the domain, sources, limit, and DNS option
        ↓
Backend builds an argument list with shell execution disabled
        ↓
Backend creates an in-memory job and starts theHarvester
        ↓
Frontend receives live WebSocket output
        ↓
REST polling is used automatically if WebSockets are unavailable
        ↓
Backend stores stdout, stderr, status, exit code, and timestamps
        ↓
Frontend extracts entities, findings, charts, and report data
```

The command is constructed as an argument list rather than a shell string. A typical command displayed in the UI is:

```text
theHarvester -d example.com -b crtsh,dnsdumpster,otx,urlscan -l 100
```

With DNS brute force enabled, the `-c` flag is appended. The frontend does not invent scan results. Emails, hosts, IPs, URLs, services, and people are displayed only when they are found in captured output.

The backend allows a maximum passive-job runtime of 15 minutes. The frontend polling window matches that limit, so a long scan is not incorrectly marked as failed after two minutes.

## 6. Using the application modules

### Overview

The Overview page shows the current target, backend connection state, recent jobs, entity totals, and shortcuts to the principal workflows.

### Domain OSINT

Use Domain OSINT for the primary theHarvester workflow:

1. Enter a domain such as `authorized.example.com`.
2. Select **Recommended** sources for a smaller initial run, or choose individual providers.
3. Start with a result limit such as `50` or `100` while testing the setup.
4. Enable DNS brute force only when it is appropriate for the authorized assessment.
5. Click **Start passive collection**.
6. Watch the live output terminal and wait for `Finished` or `Error`.

The result area contains:

| Panel | Meaning |
|---|---|
| Emails | Deduplicated email addresses detected in the captured report. |
| Hosts and domains | Domain and subdomain names found in output. |
| IP addresses | IPv4 addresses found in output. |
| People | Conservative name matches from standalone report lines. |
| URLs | HTTP and HTTPS URLs found in output. |
| Services | Passive service and port labels found in output, such as HTTP, HTTPS, SSH, or port 443. |
| Findings | Provider warnings, missing-key notices, empty-result messages, and transport diagnostics. |

A provider can finish successfully while returning zero results. For example, `0 hosts, 0 IPs, 0 emails` is an empty provider result, not necessarily a backend crash.

### DNS and Certificates

This module is a workflow shortcut for certificate-transparency and DNS-focused collection. It does not perform active DNS attacks. Enter an authorized domain and open the Domain OSINT workflow with certificate and DNS-related sources selected.

Review certificate names, expiration information, DNS records, unexpected subdomains, and third-party service names as evidence for the authorized assessment.

### Shodan Assets

The Shodan module is for **passive metadata about authorized assets**. Confirm ownership or written authorization before continuing. The backend validation endpoint is:

```text
POST /api/modules/shodan-assets/validate
```

Example:

```bash
curl -sS -X POST http://127.0.0.1:8000/api/modules/shodan-assets/validate \\
  -H 'Content-Type: application/json' \\
  -d '{"asset":"authorized.example.com","authorized":true,"limit":100}'
```

The endpoint accepts a valid domain or IP address and returns the safe scope. Shodan evidence may include hostnames, ports, banners, products, organization, and ASN. It does not open services, attempt logins, execute exploits, perform active port scanning, or access camera feeds.

After validation, configure Domain OSINT with the `shodan` source and start the passive review. The resulting services appear in the Services panel and the captured evidence remains available in the report views.

### Camera Security Audit

The Camera Audit page is a defensive checklist for cameras in an approved inventory. It records whether the operator reviewed ownership, exposure, authentication, firmware support, TLS, and network segmentation.

It does not search the internet for cameras, open video feeds, guess credentials, bypass authentication, or interact with third-party devices.

### Findings

The Findings page converts captured diagnostics into evidence-based remediation cards. Examples include incomplete provider credentials, an unexpected provider response, unavailable live transport, or no matching entities.

Findings are observations about the scan process and captured output. They are not automatic proof that a target is vulnerable.

### Reports

The Reports page shows recent in-memory jobs and provides a text-report download for the current job. Jobs are stored in memory by the local backend and are lost when the backend restarts unless you save exported reports yourself.

### Settings

Settings displays non-sensitive runtime diagnostics, including backend status, Python version, theHarvester executable detection, and Shodan key configuration status.

## 7. Backend API reference

| Method and path | Purpose |
|---|---|
| `GET /api/health` | Basic backend health check. |
| `GET /api/diagnostics` | Credential-safe runtime and configuration status. |
| `GET /api/sources` | Supported and recommended passive sources. |
| `POST /api/scan` | Create a passive theHarvester job. |
| `GET /api/jobs` | List recent in-memory jobs. |
| `GET /api/scan/{job_id}/result` | Return current job state and captured output. |
| `GET /api/scan/{job_id}/download` | Download the current text report. |
| `WS /api/scan/{job_id}/stream` | Stream command, status, output, and completion events. |
| `POST /api/modules/shodan-assets/validate` | Validate an explicitly authorized Shodan asset-review request. |
| `GET /api/runs` | List Strix-inspired run summaries. |
| `GET /api/runs/{run_id}` | Return run metadata and configuration. |
| `GET /api/runs/{run_id}/summary` | Return entity and severity summaries. |
| `GET /api/runs/{run_id}/evidence` | Return structured entities and captured lines. |
| `GET /api/runs/{run_id}/findings` | Return evidence-based findings and severity counts. |
| `GET /api/runs/{run_id}/report` | Return combined run, finding, evidence, and artifact metadata. |

## 8. Troubleshooting

### The page says the backend is offline

Check that the backend terminal is still running and test:

```bash
curl -sS http://127.0.0.1:8000/api/health
```

If the request fails, activate the virtual environment and restart Uvicorn.

### WebSocket connection fails

Install the WebSocket dependency inside the same environment used to start Uvicorn:

```bash
source .venv/Scripts/activate
python -m pip install websockets==15.0.1
```

Restart the backend. If the WebSocket still fails, the frontend should use REST polling automatically. The scan can still finish and display results.

### The UI says result polling timed out

Pull the latest code and restart both processes:

```bash
git pull origin main
source .venv/Scripts/activate
python -m pip install -e .
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

The current frontend polling period matches the backend’s 15-minute job limit. A timeout before 15 minutes usually means the browser is running an older frontend build.

### Shodan returns no data

Check diagnostics without exposing the key:

```bash
curl -sS http://127.0.0.1:8000/api/diagnostics
```

Confirm that `shodan_key_configured` is `true`, use the `shodan` source, and assess an authorized asset. A valid key does not guarantee that every target has Shodan data.

### A provider reports a missing API key

Many theHarvester providers require separate credentials. Use only the providers for which you have legitimate credentials. Missing provider keys are reported as findings and do not necessarily stop other providers.

### The scan returns zero entities

Review the captured provider output. Some sources may return no records, reject a request, or require an API key. Try a smaller set of recommended passive sources and compare results. Do not interpret an empty result as proof that an organization has no public information.

### The backend cannot find theHarvester

Run these checks inside the active virtual environment:

```bash
which python
python -m theHarvester --help
curl -sS http://127.0.0.1:8000/api/diagnostics
```

The backend first looks for `theHarvester`, `theHarvester.exe`, or `theHarvester.py`, then falls back to `python -m theHarvester`.

## 9. Capturing a bug report

Capture non-secret diagnostics:

```bash
curl -sS http://127.0.0.1:8000/api/health > health.json
curl -sS http://127.0.0.1:8000/api/diagnostics > diagnostics.json
curl -sS http://127.0.0.1:8000/api/sources > sources.json
python -m pytest -q > test-output.txt
```

For a scan-specific issue, record the operating system, Python version, Node version, frontend URL, backend URL, target type, selected sources, result limit, DNS-brute setting, job ID, displayed status, and relevant backend log lines.

Remove or redact all API keys, cookies, authorization headers, personal information, private IPs, and sensitive target details before sharing the report.

## 10. Development verification

From the repository root:

```bash
source .venv/Scripts/activate
python -m py_compile backend/main.py
python -m pytest -q
cd frontend
npm run build
```

The backend tests cover request validation, safe command construction, authorization gates, structured evidence, and findings. The frontend production build verifies that the React/Vite application compiles successfully.

## 11. Safe operating model

The project is intended to help an operator collect public evidence and improve the security posture of assets under their control. Keep target allowlists, written authorization, rate limits, provider terms, and data-retention practices outside the code where appropriate. Treat exported reports as sensitive because they may contain contact information, hostnames, IP addresses, service metadata, and operational diagnostics.

The platform should remain passive by default. Any future active testing feature should be isolated behind a separate, explicit lab-only workflow with target allowlists, authorization records, rate limits, and a review step before execution.
