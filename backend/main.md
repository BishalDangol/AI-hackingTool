# theHarvester Browser UI — Backend API

FastAPI backend that lets a browser UI run **theHarvester** OSINT scans safely, with live command + output streaming. No login required (local/private use).

## What it does
- Accepts a scan request (domain, sources, limit, DNS brute-force flag)
- Validates everything strictly, then builds the theHarvester command as an **arg list** (`shell=False` — no shell injection possible)
- Runs theHarvester as a background subprocess
- Streams the command string and live stdout/stderr line-by-line to the browser over WebSocket
- Stores full output so it can be replayed, fetched, or downloaded as a `.txt` report

## Endpoints
| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Health check |
| GET | `/api/sources` | List whitelisted theHarvester data sources |
| GET | `/api/jobs` | List recent scan jobs (last 50) |
| POST | `/api/scan` | Start a new scan (JSON or form body: `domain`, `sources[]`, `limit`, `dns_brute`) → returns `job_id` + the exact command string |
| WS | `/api/scan/{job_id}/stream` | Live stream: command → output lines → done event (status/exit code) |
| GET | `/api/scan/{job_id}/result` | Full stored output + metadata for a job |
| GET | `/api/scan/{job_id}/download` | Download the final report as `.txt` |

## Security measures
- `shell=False` everywhere — command passed as a Python list, never a shell string
- Domain regex validation (`^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`) plus an explicit blacklist of shell metacharacters
- `-b` sources checked against a hardcoded whitelist (`SUPPORTED_SOURCES`) — no raw user text reaches the command
- `limit` bounded to an integer between 1–5000
- 5-minute subprocess timeout, with the process killed on timeout
- Graceful handling of missing binary, startup failure, non-zero exit, and timeout — all surfaced to the UI as readable messages, not stack traces

## Job lifecycle
`Queued → Running → Finished` (or `Error` on failure/timeout). Jobs and their output are kept in an in-memory dict (`jobs`), so they reset on server restart — fine for a local tool, would need a real datastore for production/multi-user use.

## Notes / things to know before deploying
- No authentication — intended for local/trusted-network use only. Don't expose `/api/scan` publicly as-is.
- theHarvester binary is located via `shutil.which`, falling back to `python -m theHarvester` — make sure it's installed and on PATH.
- CORS is currently open (`allow_origins=["*"]`) — tighten this before any shared/deployed use.