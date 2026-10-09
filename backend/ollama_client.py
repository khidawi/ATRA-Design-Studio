"""
Shared Ollama client for the platform's two assistants: the Model studio's
chatbot (chat.py) and the Agent design studio's drafter (agent_chat.py).

Uses Ollama's structured-output feature (a JSON Schema in the `format`
parameter) rather than tool calling, so it works with any local model.
Runs against a locally hosted model — no API key, no per-call cost.
"""
import json
import os
from typing import Any, Dict, List, Optional

import httpx
from fastapi import HTTPException

OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.1")
# A CPU-only Ollama (e.g. in Docker without a GPU) generates a full graph in minutes, not seconds.
OLLAMA_TIMEOUT = float(os.environ.get("OLLAMA_TIMEOUT_SECONDS", "280"))


def extract_json_object(text: str) -> dict:
    """Best-effort extraction of a JSON object from a local model's raw
    output, which — unlike a provider with native structured-output
    support — may still wrap it in prose or a markdown fence despite
    instructions."""
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
        text = text.strip()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("No JSON object found in model output")
    return json.loads(text[start : end + 1])


def chat_json(
    messages: List[Dict[str, str]],
    schema: Dict[str, Any],
    *,
    temperature: float = 0.2,
    max_tokens: Optional[int] = None,
    timeout: Optional[float] = None,
) -> Dict[str, Any]:
    """Ask the local model for one JSON object matching `schema`.

    Raises HTTPException with a specific status for each way it can fail:
    503 Ollama unreachable, 504 timed out, 502 Ollama error / unusable output.
    """
    options: Dict[str, Any] = {"temperature": temperature}
    if max_tokens:
        options["num_predict"] = max_tokens

    payload = {
        "model": OLLAMA_MODEL,
        "messages": messages,
        "stream": False,
        "format": schema,
        "options": options,
    }

    try:
        resp = httpx.post(f"{OLLAMA_BASE_URL}/api/chat", json=payload, timeout=timeout or OLLAMA_TIMEOUT)
        resp.raise_for_status()
    except httpx.TimeoutException as exc:
        raise HTTPException(
            status_code=504,
            detail=f"Ollama did not answer within {(timeout or OLLAMA_TIMEOUT):.0f}s. A CPU-only model is slow; "
                    "try a shorter description, a smaller OLLAMA_MODEL, or raise OLLAMA_TIMEOUT_SECONDS.",
        ) from exc
    except httpx.ConnectError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Could not reach Ollama at {OLLAMA_BASE_URL}. "
                    "Is it installed and running? See backend/.env.example.",
        ) from exc
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Ollama returned an error: {exc.response.status_code} {exc.response.text}",
        ) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Could not reach Ollama: {exc}") from exc

    content = resp.json().get("message", {}).get("content", "")

    try:
        return json.loads(content)
    except json.JSONDecodeError:
        try:
            return extract_json_object(content)
        except (ValueError, json.JSONDecodeError) as exc:
            raise HTTPException(
                status_code=502,
                detail=f"Model did not return valid JSON: {exc}",
            ) from exc
