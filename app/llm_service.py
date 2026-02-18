import os
import asyncio
import json
import re
from typing import List, Dict, Any, Optional
import httpx

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
ATTACK_EXPLANATION_KEYS = (
    "executive_summary",
    "technical_explanation",
    "exploitation_scenario",
    "recommended_mitigation",
)


async def enrich_vulnerabilities(report_id: str, vulnerabilities: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Call OpenAI to enrich each vulnerability with an explanation and example fix.

    Returns a dict of enrichments or None if API key missing or error.
    """
    if not OPENAI_API_KEY:
        print("OPENAI_API_KEY not set; skipping LLM enrichment")
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
                    OPENAI_API_URL,
                    headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
                    json={
                        "model": "gpt-3.5-turbo",
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
                OPENAI_API_URL,
                headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
                json={
                    "model": "gpt-3.5-turbo",
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

    if not OPENAI_API_KEY or OPENAI_API_KEY.strip().lower() in {"", "your_openai_api_key_here"}:
        raise RuntimeError("OPENAI_API_KEY not set.")

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
        "model": OPENAI_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        "max_tokens": 500,
        "response_format": {"type": "json_object"},
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            response = await client.post(
                OPENAI_API_URL,
                headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
                json=request_json,
            )
            response.raise_for_status()
        except Exception as exc:
            raise RuntimeError("OpenAI request failed.") from exc

    content = (
        response.json()
        .get("choices", [{}])[0]
        .get("message", {})
        .get("content", "")
    )
    parsed = _extract_json_object(str(content))
    if not parsed:
        raise RuntimeError("OpenAI did not return valid JSON.")

    return _normalize_attack_explanation(parsed)
