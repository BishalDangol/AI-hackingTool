from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
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
