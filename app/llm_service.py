import os
import asyncio
from typing import List, Dict, Any, Optional
import httpx

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"


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
