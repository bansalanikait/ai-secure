import os
import asyncio
import json
import re
from typing import List, Dict, Any, Optional
import httpx

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
MODEL_NAME = os.getenv("MODEL_NAME", "llama-3.3-70b-versatile")
ATTACK_EXPLANATION_KEYS = (
    "executive_summary",
    "technical_explanation",
    "exploitation_scenario",
    "recommended_mitigation",
)


async def enrich_vulnerabilities(report_id: str, vulnerabilities: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Call Groq chat completions to enrich vulnerabilities.

    Returns a dict of enrichments or None if API key missing or error.
    """
    if not GROQ_API_KEY:
        print("GROQ_API_KEY not set; skipping LLM enrichment")
        return None

    async with httpx.AsyncClient(timeout=15.0) as client:
        results = []
        for vuln in vulnerabilities:
            prompt = (
                f"Explain the following vulnerability in detail and provide a contextual fix example:\n\n"
                f"Issue: {vuln.get('issue')}\n"
                f"Severity: {vuln.get('severity')}\n"
                f"Code: Provide a short, safe example fix only; do not produce harmful code."
            )
            try:
                resp = await client.post(
                    GROQ_API_URL,
                    headers={
                        "Authorization": f"Bearer {GROQ_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": MODEL_NAME,
                        "messages": [{"role": "user", "content": prompt}],
                        "max_tokens": 300,
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                text = data["choices"][0]["message"]["content"].strip()
            except Exception as e:
                print(f"LLM call failed for vuln {vuln.get('id')}: {e}")
                text = ""

            results.append({"id": vuln.get("id"), "explanation": text})

        # Also generate a summary for the whole report
        try:
            summary_prompt = (
                "Generate a short summary paragraph for a security report based on these issues:\n"
                + "\n".join([f"- {v['issue']} ({v['severity']})" for v in vulnerabilities])
            )
            resp2 = await client.post(
                GROQ_API_URL,
                headers={
                    "Authorization": f"Bearer {GROQ_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": MODEL_NAME,
                    "messages": [{"role": "user", "content": summary_prompt}],
                    "max_tokens": 150,
                },
            )
            resp2.raise_for_status()
            summary = resp2.json()["choices"][0]["message"]["content"].strip()
        except Exception as e:
            print(f"LLM summary failed: {e}")
            summary = ""

    return {"report_id": report_id, "vulnerabilities": results, "summary": summary}


def _truncate(value: Any, limit: int = 1400) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit]


def _extract_json_object(raw_text: str) -> Optional[Dict[str, Any]]:
    text = (raw_text or "").strip()
    if not text:
        return None

    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    match = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not match:
        return None

    try:
        parsed = json.loads(match.group(0))
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


def _extract_api_error_text(response: httpx.Response) -> str:
    try:
        payload = response.json()
        if isinstance(payload, dict):
            err = payload.get("error")
            if isinstance(err, dict):
                message = str(err.get("message") or "").strip()
                code = str(err.get("code") or "").strip()
                if message and code:
                    return f"{message} (code={code})"
                if message:
                    return message
        raw = (response.text or "").strip()
        return raw[:400] if raw else "Unknown error"
    except Exception:
        raw = (response.text or "").strip()
        return raw[:400] if raw else "Unknown error"


def _prepare_finding_for_prompt(finding: Dict[str, Any]) -> Dict[str, Any]:
    safe_keys = [
        "target_url",
        "parameter",
        "payload",
        "vulnerability_type",
        "severity",
        "confidence_score",
        "evidence_snippet",
        "response_status",
        "response_time_ms",
        "detection_signals",
        "stored_vulnerability_candidate",
    ]
    prepared: Dict[str, Any] = {}
    for key in safe_keys:
        if key not in finding:
            continue
        value = finding.get(key)
        if isinstance(value, (dict, list)):
            prepared[key] = value
        else:
            prepared[key] = _truncate(value, limit=800)
    return prepared


def _normalize_attack_explanation(payload: Dict[str, Any]) -> Dict[str, str]:
    normalized: Dict[str, str] = {}
    for key in ATTACK_EXPLANATION_KEYS:
        normalized[key] = _truncate(payload.get(key), limit=1500) or "Not available."
    return normalized


async def explain_attack_finding(finding: Dict[str, Any]) -> Dict[str, str]:
    """Generate a strict-JSON attack explanation for one fuzz finding."""
    if not isinstance(finding, dict) or not finding:
        raise ValueError("A non-empty fuzz finding object is required.")

    if not GROQ_API_KEY or GROQ_API_KEY.strip().lower() in {"", "your_groq_api_key_here"}:
        raise RuntimeError("GROQ_API_KEY not set.")

    payload_for_prompt = _prepare_finding_for_prompt(finding)
    prompt = (
        "You are a secure application security assistant.\n"
        "Analyze the provided fuzz finding and explain likely risk in a defensive way only.\n"
        "Do not provide exploit instructions, weaponized payloads, or step-by-step abuse guidance.\n\n"
        "Return STRICT JSON only with exactly these keys:\n"
        '  "executive_summary": string,\n'
        '  "technical_explanation": string,\n'
        '  "exploitation_scenario": string,\n'
        '  "recommended_mitigation": string\n\n'
        "The exploitation_scenario must stay high-level and non-operational.\n"
        f"Fuzz finding:\n{json.dumps(payload_for_prompt, ensure_ascii=True)}"
    )

    request_json = {
        "model": MODEL_NAME,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        "max_tokens": 500,
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            response = await client.post(
                GROQ_API_URL,
                headers={
                    "Authorization": f"Bearer {GROQ_API_KEY}",
                    "Content-Type": "application/json",
                },
                json=request_json,
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            detail = _extract_api_error_text(exc.response)
            raise RuntimeError(
                f"GROQ request failed: HTTP {exc.response.status_code} - {detail}"
            ) from exc
        except Exception as exc:
            raise RuntimeError(f"GROQ request failed: {exc}") from exc

    content = (
        response.json()
        .get("choices", [{}])[0]
        .get("message", {})
        .get("content", "")
    )
    parsed = _extract_json_object(str(content))
    if not parsed:
        raise RuntimeError("GROQ did not return valid JSON.")

    return _normalize_attack_explanation(parsed)
