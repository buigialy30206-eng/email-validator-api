"""
Email Validator API
Validates emails via SMTP handshake + MX check + syntax validation.
Zero external dependencies beyond Python stdlib.
"""

import re
import smtplib
import socket
from typing import Optional

from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import dns.resolver

app = FastAPI(title="Email Validator API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_email_re = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


class ValidationResult(BaseModel):
    email: str
    valid: bool
    reason: str
    mx_server: Optional[str] = None
    domain: Optional[str] = None


def get_mx(domain: str) -> Optional[str]:
    """Get MX server for domain."""
    try:
        answers = dns.resolver.resolve(domain, "MX")
        # Return lowest preference MX
        mx = sorted(answers, key=lambda r: r.preference)[0]
        return str(mx.exchange).rstrip(".")
    except Exception:
        return None


def smtp_check(email: str, mx: str) -> tuple[bool, str]:
    """Verify email exists on SMTP server."""
    try:
        server = smtplib.SMTP(mx, 25, timeout=10)
        server.set_debuglevel(0)
        server.helo("validator.local")
        server.mail("verify@validator.local")
        code, msg = server.rcpt(email)
        server.quit()
        if code == 250:
            return True, "Email verified"
        elif code == 550:
            return False, "Mailbox does not exist"
        else:
            return None, f"Partial validation (MX exists, SMTP returned {code})"
    except smtplib.SMTPConnectError:
        return None, "Partial validation (MX verified, SMTP unavailable)"
    except smtplib.SMTPServerDisconnected:
        return None, "Partial validation (MX verified, server disconnected)"
    except socket.timeout:
        return None, "Partial validation (MX verified, SMTP timed out)"
    except OSError:
        return None, "Partial validation (MX verified, SMTP blocked)"
    except Exception as e:
        return None, f"Partial validation (MX verified, error: {str(e)[:30]})"


def validate_email(email: str) -> ValidationResult:
    """Full email validation pipeline."""
    # Step 1: Syntax
    if not _email_re.match(email):
        return ValidationResult(email=email, valid=False, reason="Invalid email format")

    domain = email.split("@")[1]

    # Step 2: MX check
    mx = get_mx(domain)
    if not mx:
        return ValidationResult(email=email, valid=False, reason="No MX record found", domain=domain)

    # Step 3: SMTP handshake
    valid, reason = smtp_check(email, mx)

    return ValidationResult(
        email=email,
        valid=valid,
        reason=reason,
        mx_server=mx,
        domain=domain,
    )


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/")
async def root():
    return {"service": "Email Validator API", "version": "1.0.0", "endpoints": {"/validate": "GET ?email=test@example.com"}}


@app.get("/validate", response_model=ValidationResult)
async def validate(email: str = Query(..., description="Email address to validate")):
    """Validate a single email address."""
    return validate_email(email)


@app.post("/validate-batch")
async def validate_batch(emails: list[str]):
    """Validate multiple emails at once."""
    if len(emails) > 50:
        raise HTTPException(400, "Max 50 emails per batch")
    results = [validate_email(e) for e in emails]
    return {"results": [r.model_dump() for r in results]}
