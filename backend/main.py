import asyncio
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

app = FastAPI(title="Passive Domain Inventory API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class DomainRequest(BaseModel):
    domain: str

@app.get("/api/health")
def health_check():
    return {"status": "healthy"}

@app.get("/api/logs-stream")
async def logs_stream(domain: str):
    async def log_generator():
        logs = [
            f"[INFO] Initializing inventory check for domain: {domain}",
            "[INFO] Checking local cache for existing records...",
            "[INFO] Querying passive database crt.sh...",
            "[SUCCESS] Found 3 subdomain certificates in crt.sh.",
            "[INFO] Querying public DNS records (A, MX, TXT)...",
            "[SUCCESS] Retrieved MX records: mail.protonmail.ch",
            f"[SUCCESS] Retrieved A records: 192.0.2.24 for {domain}",
            "[INFO] Analyzing DNS security policy (SPF/DMARC)...",
            "[WARNING] DMARC policy not set to reject/quarantine (action=none).",
            "[INFO] Storing passive records in catalog...",
            "[INFO] Inventory indexing complete."
        ]
        for log in logs:
            yield f"data: {log}\n\n"
            await asyncio.sleep(0.8)

    return StreamingResponse(log_generator(), media_type="text/event-stream")

@app.post("/api/domain-info")
def get_domain_info(payload: DomainRequest):
    domain = payload.domain.strip().lower()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain name is required")
        
    # Safe mock data demonstrating passive DNS and asset inventory representation
    return {
        "domain": domain,
        "status": "monitored",
        "dns_records": {
            "A": ["192.0.2.24", "198.51.100.12"],
            "MX": [f"mail.protonmail.ch", f"mailsec.{domain}"],
            "TXT": ["v=spf1 include:_spf.google.com ~all", "dmarc=action=none"]
        },
        "passive_sources": ["crt.sh", "dnsdumpster", "subdomaincenter"]
    }
