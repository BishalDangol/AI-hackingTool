## Documentation

The complete operator and user guide is available at [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md). It covers Windows/Git Bash setup, normal backend and frontend startup, module usage, scan lifecycle, results, API endpoints, troubleshooting, and bug-report capture. The complete APA 7 final-year project report is available at [`docs/FYP_REPORT_APA7.md`](docs/FYP_REPORT_APA7.md).

## How to Run the Project

### Prerequisites

Make sure the following are installed on your system before proceeding:

| Requirement | Minimum Version | Notes |
|---|---|---|
| Python | 3.12+ | For the backend (FastAPI + uvicorn) |
| Node.js | 18+ | For the frontend (React + Vite) |
| npm | 9+ | Comes bundled with Node.js |

---

### Running the Backend

The backend is a **FastAPI** server that handles scan jobs, WebSocket streaming, and REST endpoints.

#### Step 1 — Create & activate a virtual environment

**Windows (PowerShell):**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**Linux / macOS:**
```bash
python -m venv .venv
source .venv/bin/activate
```

#### Step 2 — Install Python dependencies

```bash
pip install -e .
pip install fastapi uvicorn pydantic
```

> Alternatively, if you use `uv`:
> ```bash
> curl -LsSf https://astral.sh/uv/install.sh | sh
> uv sync
> ```

#### Step 3 — Start the backend server

```bash
# Standard (virtualenv activated):
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload

# Windows explicit path (no activation needed):
.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload

# Using uv:
uv run uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

The backend API will be available at: **`http://127.0.0.1:8000`**

You can verify it is running by visiting: `http://127.0.0.1:8000/api/health`
Expected response: `{"status": "healthy"}`

---

### Running the Frontend

The frontend is a **React** Single-Page Application (SPA) built with **Vite**.

#### Step 1 — Navigate to the frontend directory

```bash
cd frontend
```

#### Step 2 — Install Node.js dependencies

```bash
npm install
```

> This only needs to be done once (or after pulling new changes that modify `package.json`).

#### Step 3 — Start the development server

```bash
npm run dev
```

The UI will be available at: **`http://localhost:5173`**

Open this URL in any modern browser. The React app will automatically connect to the backend at `http://127.0.0.1:8000`.

---

### Running Both Together (Quick Reference)

Open **two separate terminals** and run:

| Terminal | Command | Serves |
|---|---|---|
| Terminal 1 (Backend) | `python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload` | `http://127.0.0.1:8000` |
| Terminal 2 (Frontend) | `cd frontend && npm run dev` | `http://localhost:5173` |

Then open **`http://localhost:5173`** in your browser.

---

## Core Features & Security Guarantees

### 🛡️ Ironclad Local Subprocess Security
Even though this interface is built for local/private use without login, **strict security hardening** is enforced across all API endpoints:
- **No `shell=True` Execution**: Commands are constructed purely as Python lists (e.g. `["theHarvester", "-d", domain, ...]`) and passed to `subprocess.Popen` / `asyncio.create_subprocess_exec(shell=False)` to completely eliminate shell injection risks.
- **Strict Domain Validation**: Target domains are strictly checked against alphanumeric regex (`^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`) and blocked if any dangerous characters (spaces, semicolons, quotes, pipes, backticks, `$()`, `&&`) are found.
- **Whitelisted Data Sources**: Data sources passed to `-b` (`--source`) are validated against a fixed backend whitelist (`SUPPORTED_SOURCES`). Raw user text or unverified engines are rejected at API entry.
- **Limit Range Checks**: The `-l` (`--limit`) flag is strictly bounded between `1` and `5000`.
- **Enforced Subprocess Timeout**: Scans enforce an automatic **5-minute (300s) timeout**. If a scan exceeds this limit, the backend cleanly terminates the child process and marks the job as timed out.

### 💻 Live Monospace Terminal & UX
- **Command Construction Display**: Shows the exact, human-readable command string (e.g. `theHarvester -d example.com -b crtsh,dnsdumpster -l 500 -c`) prior to execution.
- **Real-Time WebSocket Stream**: Live `stdout` and `stderr` logs stream directly into an auto-scrolling terminal panel (`/api/scan/{job_id}/stream`).
- **Pause-on-Scroll-Up Behavior**: Scrolling up inside the terminal automatically pauses auto-scroll so you can inspect historical output without interruption. A floating `[↓ Resume Auto-scroll]` button lets you instantly jump to the bottom and resume tracking.
- **Syntax Color Coding**: Lines containing `[SUCCESS]`, `[ERROR]`, `[WARNING]`, and `[STDERR]` are color-coded for fast threat intelligence analysis.
- **Download Output (.txt)**: Instantly download the complete reconnaissance report with full metadata once the scan finishes (`GET /api/scan/{job_id}/download`).

---

## 📡 REST API & WebSocket Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Health check (`{"status": "healthy"}`). |
| `GET` | `/api/sources` | Returns whitelisted `theHarvester` engines and recommended UI presets. |
| `POST` | `/api/scan` | Accepts JSON (`domain`, `sources`, `limit`, `dns_brute`) or form data. Strictly validates, triggers async background job, and returns `job_id`. |
| `WS` | `/api/scan/{job_id}/stream` | Streams: `(a)` constructed command string first, `(b)` live output lines, `(c)` final status/exit code. |
| `GET` | `/api/scan/{job_id}/result` | Returns the complete stored output, status, and exit code for any completed job. |
| `GET` | `/api/scan/{job_id}/download` | Returns the final log report formatted as a downloadable `.txt` file. |

---

About
-----
theHarvester is a simple to use, yet powerful tool designed to be used during the reconnaissance stage of a red
team assessment or penetration test. It performs open source intelligence (OSINT) gathering to help determine
a domain's external threat landscape. The tool gathers names, emails, IPs, subdomains, and URLs by using
multiple public resources that include:

## Package versions
[![Packaging status](https://repology.org/badge/vertical-allrepos/theharvester.svg)](https://repology.org/project/theharvester/versions)

Install and dependencies
------------------------
* Python 3.12 or higher.
* https://github.com/laramies/theHarvester/wiki/Installation

Install uv:
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

Clone the repository:
   ```bash
   git clone https://github.com/laramies/theHarvester
   cd theHarvester
   ```

Install dependencies and create a virtual environment:
   ```bash
   uv sync
   ```

Run theHarvester:
   ```bash
   uv run theHarvester
   ```

## Development

To install development dependencies:
```bash
uv sync --all-groups
```

To run tests:
```bash
uv run pytest
```

To run linting and formatting:
```bash
uv run ruff check
```
```bash
uv run ruff format
```

To protect the optional `/additional/*` REST API routes, set `THEHARVESTER_API_KEY` and pass the same value in the `X-API-Key` header. Those routes return `503` when the key is not configured.

Passive modules
---------------

* baidu: Baidu search engine (https://www.baidu.com)

* bevigil: CloudSEK BeVigil scans mobile application for OSINT assets (https://bevigil.com/osint-api)

* brave: Brave search engine - now uses official Brave Search API (https://api-dashboard.search.brave.com)

* bufferoverun: Fast domain name lookups for TLS certificates in IPv4 space (https://tls.bufferover.run)

* builtwith: Find out what websites are built with (https://builtwith.com)

* censys: Uses certificates searches to enumerate subdomains and gather emails (https://censys.io)

* certspotter: Cert Spotter monitors Certificate Transparency logs (https://sslmate.com/certspotter)

* criminalip: Specialized Cyber Threat Intelligence (CTI) search engine (https://www.criminalip.io)

* crtsh: Comodo Certificate search (https://crt.sh)

* dehashed: Take your data security to the next level is (https://dehashed.com)

* dnsdumpster: Domain research tool that can discover hosts related to a domain (https://dnsdumpster.com)

* duckduckgo: DuckDuckGo search engine (https://duckduckgo.com)

* dymo: Dymo API data verifier - confirms domains, surfaces typo suggestions and MX/fraud signals (https://dymo.tpeoficial.com)

* fofa: FOFA search eingine (https://en.fofa.info)

* fullhunt: Next-generation attack surface security platform (https://fullhunt.io)

* github-code: GitHub code search engine (https://www.github.com)

* hackertarget: Online vulnerability scanners and network intelligence to help organizations (https://hackertarget.com)

* haveibeenpwned: Check if your email address is in a data breach (https://haveibeenpwned.com)

* hunter: Hunter search engine (https://hunter.io)

* hunterhow: Internet search engines for security researchers (https://hunter.how)

* intelx: Intelx search engine (https://intelx.io)

* leakix: LeakIX search engine (https://leakix.net)

* leaklookup: Data breach search engine (https://leak-lookup.com)

* mojeek: Mojeek search engine (https://www.mojeek.com)

* netlas: A Shodan or Censys competitor (https://app.netlas.io)

* onyphe: Cyber defense search engine (https://www.onyphe.io)

* otx: AlienVault open threat exchange (https://otx.alienvault.com)

* pentesttools: Cloud-based toolkit for offensive security testing, focused on web applications and network penetration testing (https://pentest-tools.com)

* projecdiscovery: Actively collects and maintains internet-wide assets data, to enhance research and analyse changes around DNS for better insights (https://chaos.projectdiscovery.io)

* rapiddns: DNS query tool which make querying subdomains or sites of a same IP easy (https://rapiddns.io)

* rocketreach: Access real-time verified personal/professional emails, phone numbers, and social media links (https://rocketreach.co)

* securityscorecard: helps TPRM and SOC teams detect, prioritize, and remediate vendor risk across their entire supplier ecosystem at scale (https://securityscorecard.com)

* securityTrails: Security Trails search engine, the world's largest repository of historical DNS data (https://securitytrails.com)

* sherlockeye: Reverse Lookup & AI-Powered OSINT (https://sherlockeye.io)

* -s, --shodan: Shodan search engine will search for ports and banners from discovered hosts (https://shodan.io). In this project it is limited to passive metadata for domains and assets you own or are explicitly authorized to assess; it must not be used to locate, access, or view exposed CCTV cameras.

* subdomaincenter: A subdomain finder tool used to find subdomains of a given domain (https://www.subdomain.center)

* subdomainfinderc99: A subdomain finder is a tool used to find the subdomains of a given domain (https://subdomainfinder.c99.nl)

* thc: Free subdomain enumeration service with no API key required (https://ip.thc.org)

* threatminer: Data mining for threat intelligence (https://www.threatminer.org)

* tomba: Tomba search engine (https://tomba.io)

* urlscan: A sandbox for the web that is a URL and website scanner (https://urlscan.io)

* venacus: Venacus search engine (https://venacus.com)

* virustotal: Domain search (https://www.virustotal.com)

* whoisxml: Subdomain search (https://subdomains.whoisxmlapi.com/api/pricing)

* yahoo: Yahoo search engine (https://www.yahoo.com)

* windvane: Windvane search engine (https://windvane.lichoin.com)

* zoomeye: China's version of Shodan (https://www.zoomeye.org)

Active modules
--------------
* DNS brute force: dictionary brute force enumeration
* Screenshots: Take screenshots of subdomains that were found

Modules that require an API key
-------------------------------
Documentation to setup API keys can be found at - https://github.com/laramies/theHarvester/wiki/Installation#api-keys

* bevigil - 50 free queries/month. 1k queries/month $50
* brave - free plan available. Pro plans for higher limits
* bufferoverun - 100 free queries/month. 10k/month $25
* builtwith - 50 free queries ever. $2950/yr
* censys - 500 credits $100
* criminalip - 100 free queries/month. 700k/month $59
* dehashed - 500 credts $15, 5k credits $150
* dnsdumpster - 50 free querries/day, $49
* dymo - free tier available, paid plans for higher limits
* fofa - query credits 10,000/month. 100k results/month $25
* fullhunt - 50 free queries. 200 queries $29/month, 500 queries $59 
* github-code
* haveibeenpwned - 10 email searches/min $4.50, 50 email searches/min $22
* hunter - 50 free credits/month. 12k credits/yr $34
* hunterhow - 10k free API results per 30 days. 50k API results per 30 days $10
* intelx - free account is very limited. Business acount $2900
* leakix - free 25 results pages, 3000 API requests/month. Bounty Hunter $29
* leaklookup - 20 credits $10, 50 credits $20, 140 credits $50, 300 credits $100
* mojeek - 5000 free credits $6.50, $1.30 CPM (Personal), $2.60 CPM (Startup), $3.90 CPM (Business)
* netlas - 50 free requests/day. 1k requests $49, 10k requests $249
* onyphe - 10M results/month $587
* pentesttools - 5 assets netsec $95/month, 5 assets webnetsec $140/month
* projecdiscovery - requires work email. Free monthly discovery and vulnerability scans on sign-up email domain, enterprise $
* rocketreach - 100 email lookups/month $48, 250 email lookups/month $108
* securityscorecard - requires a work email
* securityTrails - 50 free queries/month. 20k queries/month $500
* sherlockeye - Intermediate $46 month, Advanced $120 month. Enterprise available.
* shodan - Freelancer $69 month, Small Business $359 month
* tomba - 25 free searches/month. 1k searches/month $39, 5k searches/month $89
* venacus - 1 free search/day. 10 searches/day $12, 30 searches/day $36
* virustotal - 500 free lookups/day, 15.5k lookups/month. Busines accounts requires a work email
* whoisxml - 2k queries $50, 5k queries $105
* windvane - 100 free queries
* zoomeye - 5 free results/day. 30/results/day $190/yr

## Shodan configuration and troubleshooting

Use Shodan only for passive metadata about domains and infrastructure that you own or are explicitly authorized to assess. Do not use this project to locate, access, or view exposed CCTV cameras.

### Recommended local configuration

Create a local environment variable before starting the backend. The value is read by the Shodan integration and is never returned by the diagnostics endpoint:

```bash
export SHODAN_API_KEY='paste-your-shodan-key-here'
uv run uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

Alternatively, place the key in `~/.theHarvester/api-keys.yaml` under `apikeys.shodan.key`. Keep real credentials out of Git. The repository’s `theHarvester/data/api-keys.yaml` is only a non-secret empty template.

### Smooth local startup

In terminal one, install and start the backend:

```bash
uv sync --all-groups
export SHODAN_API_KEY='paste-your-shodan-key-here'
uv run uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

In terminal two, install and start the frontend:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. Confirm the backend first at `http://127.0.0.1:8000/api/health`, then inspect `http://127.0.0.1:8000/api/diagnostics`. The diagnostics response intentionally reports only whether a Shodan key is configured, its source (`environment` or `yaml`), the Python version, and the executable path.

### Docker configuration

For Docker Compose, export the key before starting the service:

```bash
export SHODAN_API_KEY='paste-your-shodan-key-here'
docker compose up --build
```

If you prefer YAML configuration, edit a local ignored copy and mount it to `/root/.theHarvester/api-keys.yaml`; do not commit the populated file.

### Capturing a reproducible bug report

Run the following commands and save their output when a scan fails:

```bash
curl -sS http://127.0.0.1:8000/api/health
curl -sS http://127.0.0.1:8000/api/diagnostics
curl -sS http://127.0.0.1:8000/api/sources
uv run pytest -q
```

Then record the target domain, selected source names, limit, whether DNS brute force was enabled, the returned `job_id`, the `/api/scan/{job_id}/result` response, and the backend terminal log. Never include `SHODAN_API_KEY` or the contents of a populated `api-keys.yaml` in a bug report.

## Windows PowerShell workflow

From the repository root, create and activate the virtual environment with the Python launcher:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
```

Configure Shodan without writing the key into the repository:

```powershell
$env:SHODAN_API_KEY = "your-real-key"
```

Start the backend in the activated environment:

```powershell
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

In a second PowerShell window, start the frontend:

```powershell
cd frontend
npm install
npm run dev
```

The terminal view receives each output line through the WebSocket stream. After output arrives, the **Scan result charts** panel summarizes the captured lines with entity indicators, event severity, and reported source labels. The charts are based only on actual captured output; when a provider returns no matching data, the panel displays an empty-state message rather than fabricated counts.

For a reproducible Windows bug capture, use:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/health
Invoke-RestMethod http://127.0.0.1:8000/api/diagnostics
Invoke-RestMethod http://127.0.0.1:8000/api/sources
python -m pytest -q
```

If PowerShell blocks script activation, run `Set-ExecutionPolicy -Scope Process Bypass` only for the current PowerShell process, then activate `.venv` again. Do not paste the value of `$env:SHODAN_API_KEY` into screenshots, logs, issues, or reports.
