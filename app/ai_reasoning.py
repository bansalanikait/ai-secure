import json
import os
import re
from typing import Any, Dict, List, Optional

import httpx

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
AI_REASONING_ANOMALY_THRESHOLD = float(
    os.getenv("AI_REASONING_ANOMALY_THRESHOLD", "0.75")
)
MAX_REFINED_PAYLOAD_LENGTH = 180
ALLOWED_ESCALATION_CATEGORIES = {
    "sql_injection",
    "xss",
    "path_traversal",
    "command_injection",
}


def should_invoke_ai_reasoning(anomaly_score: float, threshold: float) -> bool:
    if threshold <= 0:
        threshold = AI_REASONING_ANOMALY_THRESHOLD
    if not OPENAI_API_KEY:
        return False
    if OPENAI_API_KEY.strip().lower() in {"", "your_openai_api_key_here"}:
        return False
    return anomaly_score >= threshold


def _truncate(text: str, limit: int = 1200) -> str:
    if not text:
        return ""
    clean = text.strip()
    if len(clean) <= limit:
        return clean
    return clean[:limit]


def _extract_json_object(text: str) -> Optional[Dict[str, Any]]:
    raw = (text or "").strip()
    if not raw:
        return None

    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    match = re.search(r"\{.*\}", raw, flags=re.DOTALL)
    if not match:
        return None

    try:
        parsed = json.loads(match.group(0))
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


def _sanitize_refined_payload(payload: str) -> str:
    value = (payload or "").replace("\r", " ").replace("\n", " ").strip()
    value = re.sub(r"\s+", " ", value)
    if len(value) > MAX_REFINED_PAYLOAD_LENGTH:
        value = value[:MAX_REFINED_PAYLOAD_LENGTH]
    return value


async def reason_on_anomaly(
    baseline_response: Dict[str, Any],
    fuzz_response: Dict[str, Any],
    detection_signals: Dict[str, Any],
    anomaly_score: float,
    original_payload: str,
    parameter: str,
    category: str,
) -> Optional[Dict[str, Any]]:
    if not OPENAI_API_KEY or OPENAI_API_KEY.strip().lower() in {"", "your_openai_api_key_here"}:
        return None

    baseline_body = _truncate(str(baseline_response.get("body") or ""))
    fuzz_body = _truncate(str(fuzz_response.get("body") or ""))

    prompt = (
        "You are a secure web testing reasoning assistant. "
        "Given baseline and fuzz responses, infer the most likely vulnerability and "
        "propose one safer refined payload for verification only. "
        "Also estimate exploitation likelihood and whether to escalate payload categories.\n\n"
        "Return STRICT JSON with keys:\n"
        '  "likely_vulnerability": string,\n'
        '  "exploitation_likelihood": number (0.0-1.0),\n'
        '  "escalate_categories": array of strings from [sql_injection,xss,path_traversal,command_injection],\n'
        '  "refined_payload": string,\n'
        '  "rationale": string\n\n'
        "Constraints:\n"
        "- Keep refined payload short and non-destructive.\n"
        "- Do not propose exploitation chains.\n"
        "- If uncertain, set likely_vulnerability to 'inconclusive'.\n\n"
        f"Input parameter: {parameter}\n"
        f"Category: {category}\n"
        f"Current anomaly score: {anomaly_score}\n"
        f"Original payload: {original_payload}\n"
        f"Detection signals: {json.dumps(detection_signals, ensure_ascii=True)}\n\n"
        f"Baseline response:\nStatus={baseline_response.get('status_code')}, "
        f"Len={baseline_response.get('length')}, "
        f"ContentType={baseline_response.get('content_type')}\n"
        f"BodySnippet:\n{baseline_body}\n\n"
        f"Fuzzed response:\nStatus={fuzz_response.get('status_code')}, "
        f"Len={fuzz_response.get('length')}, "
        f"ContentType={fuzz_response.get('content_type')}\n"
        f"BodySnippet:\n{fuzz_body}\n"
    )

    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            resp = await client.post(
                OPENAI_API_URL,
                headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
                json={
                    "model": OPENAI_MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.1,
                    "max_tokens": 220,
                },
            )
            resp.raise_for_status()
            content = (
                resp.json()
                .get("choices", [{}])[0]
                .get("message", {})
                .get("content", "")
            )
    except Exception as exc:
        print(f"AI reasoning request failed: {exc}")
        return None

    parsed = _extract_json_object(str(content))
    if not parsed:
        return None

    likely_vulnerability = str(parsed.get("likely_vulnerability") or "").strip() or "inconclusive"
    refined_payload = _sanitize_refined_payload(str(parsed.get("refined_payload") or ""))
    rationale = _truncate(str(parsed.get("rationale") or ""), limit=400)
    exploitation_likelihood_raw = parsed.get("exploitation_likelihood")
    try:
        exploitation_likelihood = float(exploitation_likelihood_raw)
    except Exception:
        exploitation_likelihood = 0.0
    if exploitation_likelihood < 0.0:
        exploitation_likelihood = 0.0
    if exploitation_likelihood > 1.0:
        exploitation_likelihood = 1.0

    escalate_categories_raw = parsed.get("escalate_categories")
    escalate_categories: List[str] = []
    if isinstance(escalate_categories_raw, list):
        for item in escalate_categories_raw:
            category = str(item or "").strip().lower()
            if category in ALLOWED_ESCALATION_CATEGORIES and category not in escalate_categories:
                escalate_categories.append(category)

    if not refined_payload:
        return None

    return {
        "likely_vulnerability": likely_vulnerability,
        "exploitation_likelihood": exploitation_likelihood,
        "escalate_categories": escalate_categories,
        "refined_payload": refined_payload,
        "rationale": rationale,
    }


__all__ = [
    "AI_REASONING_ANOMALY_THRESHOLD",
    "reason_on_anomaly",
    "should_invoke_ai_reasoning",
]
