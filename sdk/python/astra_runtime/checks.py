"""
Local text checks for a language model's prompts and replies. Nothing here leaves your process: it scans the text where it runs and returns yes/no flags, and
only those flags are sent to ASTRA (ASTRA never sees a prompt or a reply).

    from astra_runtime.checks import llm_flags
    mon.log(inputs={...}, output="reply text", flags=llm_flags(prompt=prompt, output=reply))      # or: mon.log(..., prompt_text=prompt, output_text=reply)

These are pattern matches, not proof. They find the common shapes (an email address, a card number that passes the Luhn check, an access key, a private-key
header, "ignore previous instructions"), so a match can be a false alarm and a miss is possible. Add your own patterns for what matters in your business.
"""
import re
from typing import Dict, Optional, Pattern

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE = re.compile(r"(?<!\d)(?:\+\d{1,3}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}|\(\d{3}\)[\s.-]?\d{3}[\s.-]\d{4}|\d{3}[\s.-]\d{3}[\s.-]\d{4})(?!\d)")
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
_SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
_NINO = re.compile(r"\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b")
_SECRETS = [re.compile(p) for p in (
    r"AKIA[0-9A-Z]{16}", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", r"\bsk-[A-Za-z0-9_-]{20,}", r"\bgh[pousr]_[A-Za-z0-9]{30,}", r"\bxox[abprs]-[A-Za-z0-9-]{10,}",
    r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", r"(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*[^\s\"']{8,}", r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{24,}")]
_INJECTION = re.compile(r"(?i)\b(?:ignore|disregard|forget)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all)\b[^.\n]{0,30}\b(?:instructions?|rules?|prompts?)\b|\b(?:reveal|show|print|repeat)\b[^.\n]{0,30}\b(?:system|hidden|initial) (?:prompt|instructions?)\b|\bdeveloper mode\b|\bjailbreak\b|\byou are now (?:dan|an? unrestricted)")


def _luhn(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total, alt = total + d, not alt
    return total % 10 == 0


def has_pii(text: str, extra: Optional[Pattern] = None) -> bool:
    if not text:
        return False
    if _EMAIL.search(text) or _SSN.search(text) or _IBAN.search(text) or _NINO.search(text) or (extra and extra.search(text)):
        return True
    if _PHONE.search(text):
        return True
    return any(_luhn(re.sub(r"\D", "", m.group())) for m in _CARD.finditer(text) if 13 <= len(re.sub(r"\D", "", m.group())) <= 19)


def has_secret(text: str) -> bool:
    return bool(text) and any(p.search(text) for p in _SECRETS)


def has_injection(text: str) -> bool:
    return bool(text) and bool(_INJECTION.search(text))


def llm_flags(prompt: Optional[str] = None, output: Optional[str] = None) -> Dict[str, bool]:
    """The five safety flags ASTRA understands. Only keys that are true are returned."""
    out = {"pii_in_prompt": has_pii(prompt or ""), "secret_in_prompt": has_secret(prompt or ""), "pii_in_output": has_pii(output or ""), "secret_in_output": has_secret(output or ""),
           "injection_suspected": has_injection(prompt or "") or has_injection(output or "")}
    return {k: True for k, v in out.items() if v}
