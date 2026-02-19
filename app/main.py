import asyncio
import json
import os
from datetime import datetime
from io import BytesIO
from typing import Any, Dict, List

from fastapi import (
    BackgroundTasks,
    FastAPI,
    File,
    HTTPException,
    Request,
    UploadFile,
    status,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel

from bson.objectid import ObjectId
from app.database import get_reports_collection, MONGO_URI
from app.scanner import scan_code, scan_directory
from app.crawler import crawl_site
from app.fuzzing_engine import fuzz_from_crawler_output
from app.llm_service import enrich_vulnerabilities, explain_attack_finding
from app.pdf_service import generate_pdf
from app.utils import validate_github_url, download_github_repo, cleanup_temp_directory
from app.vulnerability_taxonomy import get_vulnerability_taxonomy


class ScanRepoRequest(BaseModel):
    repo_url: str


class CrawlRequest(BaseModel):
    target_url: str


class AttackExplanationResponse(BaseModel):
    executive_summary: str
    technical_explanation: str
    exploitation_scenario: str
    recommended_mitigation: str


class ScanWebsiteRequest(BaseModel):
    target_url: str


app = FastAPI()
MAX_AI_EXPLANATIONS_PER_SCAN = 5
AI_EXPLANATION_MIN_INTERVAL_SECONDS = 0.25

# CORS - allow configured origins in production, default to localhost for dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static frontend
app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.exception_handler(RequestValidationError)
async def request_validation_exception_handler(
    request: Request, exc: RequestValidationError
):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": "Malformed input"},
    )


def _parse_object_id(report_id: str) -> ObjectId:
    try:
        return ObjectId(report_id)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid report id"
        ) from exc


def _serialize_report(doc: Dict[str, Any]) -> Dict[str, Any]:
    serialized = dict(doc)
    serialized["_id"] = str(serialized["_id"])
    report_type = serialized.get("type") or (
        "repo" if serialized.get("repo_url") else "file"
    )
    serialized["type"] = report_type
    vulnerabilities = serialized.get("vulnerabilities") or []
    serialized["total_vulnerabilities"] = serialized.get("total_vulnerabilities") or len(
        vulnerabilities
    )
    serialized["total_files"] = serialized.get("total_files") or (
        1 if report_type == "file" else 0
    )
    return serialized


async def _get_reports_collection_or_503():
    try:
        return await get_reports_collection()
    except Exception as exc:
        print(f"Database connection error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        ) from exc


def _web_grade_from_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _has_openai_api_key() -> bool:
    key = str(os.getenv("OPENAI_API_KEY") or "").strip()
    if not key:
        return False
    return key.lower() != "your_openai_api_key_here"


def _fallback_explanation_for_finding(
    finding: Dict[str, Any], reason: str = ""
) -> Dict[str, str]:
    vulnerability_type = str(finding.get("vulnerability_type") or "Potential issue").strip()
    taxonomy = get_vulnerability_taxonomy(vulnerability_type)
    owasp = taxonomy.get("owasp_category") or "Unmapped OWASP category"
    cwe = taxonomy.get("cwe_id") or "Unmapped CWE"

    normalized = vulnerability_type.lower()
    if "sql" in normalized:
        mitigation = (
            "Use parameterized queries/prepared statements, enforce strict input validation, "
            "and avoid building SQL from raw user input."
        )
    elif "xss" in normalized or "cross site" in normalized:
        mitigation = (
            "Apply contextual output encoding, sanitize untrusted input, and enforce a strict "
            "Content Security Policy (CSP)."
        )
    elif "command" in normalized:
        mitigation = (
            "Avoid shell invocation with untrusted input, use allowlists, and execute commands "
            "through safe APIs with strict argument handling."
        )
    elif "path" in normalized and "travers" in normalized:
        mitigation = (
            "Normalize and validate filesystem paths, enforce directory allowlists, and block "
            "relative traversal sequences."
        )
    else:
        mitigation = (
            "Validate and constrain input, enforce safe output handling, and harden server-side "
            "error handling and access controls."
        )

    reason_suffix = f" ({reason})" if reason else ""
    return {
        "executive_summary": (
            f"Automated analysis indicates a potential {vulnerability_type} finding{reason_suffix}."
        ),
        "technical_explanation": (
            f"The detection signals for this finding suggest behavior consistent with {vulnerability_type}. "
            f"Taxonomy mapping: {owasp}, {cwe}."
        ),
        "exploitation_scenario": (
            "An attacker may manipulate user-controlled input to trigger unintended server behavior "
            "or expose sensitive application logic."
        ),
        "recommended_mitigation": mitigation,
    }


def _unique_keep_order(values: List[Any]) -> List[Any]:
    seen: set[str] = set()
    output: List[Any] = []
    for value in values:
        try:
            key = json.dumps(value, sort_keys=True, ensure_ascii=True)
        except Exception:
            key = str(value)
        if key in seen:
            continue
        seen.add(key)
        output.append(value)
    return output


def _merge_signal_values(values: List[Any]) -> Any:
    valid = [value for value in values if value is not None]
    if not valid:
        return None

    if all(isinstance(value, bool) for value in valid):
        return any(valid)

    if all(isinstance(value, (int, float)) and not isinstance(value, bool) for value in valid):
        return max(valid)

    if all(isinstance(value, dict) for value in valid):
        merged: Dict[str, Any] = {}
        all_keys = set().union(*(value.keys() for value in valid))
        for key in all_keys:
            merged_value = _merge_signal_values(
                [value.get(key) for value in valid if key in value]
            )
            if merged_value is not None:
                merged[key] = merged_value
        return merged

    if all(isinstance(value, list) for value in valid):
        merged_list: List[Any] = []
        for value in valid:
            merged_list.extend(value)
        return _unique_keep_order(merged_list)

    return valid[0]


def _merge_detection_signals(signals_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    valid = [signals for signals in signals_list if isinstance(signals, dict)]
    if not valid:
        return {}

    merged: Dict[str, Any] = {}
    all_keys = set().union(*(signals.keys() for signals in valid))
    for key in all_keys:
        merged_value = _merge_signal_values(
            [signals.get(key) for signals in valid if key in signals]
        )
        if merged_value is not None:
            merged[key] = merged_value
    return merged


def _deduplicate_scan_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[tuple[str, str, str], List[Dict[str, Any]]] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        target_url = str(finding.get("target_url") or "").strip()
        parameter = str(finding.get("parameter") or "").strip()
        vulnerability_type = str(finding.get("vulnerability_type") or "Potential issue").strip()
        group_key = (target_url, parameter, vulnerability_type.lower())
        grouped.setdefault(group_key, []).append(finding)

    deduplicated: List[Dict[str, Any]] = []
    for group in grouped.values():
        ranked = sorted(
            group,
            key=lambda item: float(item.get("confidence_score") or 0.0),
            reverse=True,
        )
        base = dict(ranked[0])

        payload_examples_raw: List[str] = []
        for item in ranked:
            payload = str(item.get("payload") or "").strip()
            if payload:
                payload_examples_raw.append(payload)
            existing_examples = item.get("payload_examples") or []
            if isinstance(existing_examples, list):
                for example in existing_examples:
                    text = str(example or "").strip()
                    if text:
                        payload_examples_raw.append(text)
        payload_examples = _unique_keep_order(payload_examples_raw)

        if payload_examples:
            base["payload_examples"] = payload_examples
            if not str(base.get("payload") or "").strip():
                base["payload"] = payload_examples[0]

        base["stored_vulnerability_candidate"] = any(
            bool(item.get("stored_vulnerability_candidate")) for item in ranked
        )
        base["detection_signals"] = _merge_detection_signals(
            [item.get("detection_signals") for item in ranked]
        )

        if any(isinstance(item.get("flow_chain_evidence"), list) for item in ranked):
            chains: List[Any] = []
            for item in ranked:
                evidence = item.get("flow_chain_evidence")
                if isinstance(evidence, list):
                    chains.extend(evidence)
            base["flow_chain_evidence"] = _unique_keep_order(chains)

        deduplicated.append(base)

    deduplicated.sort(
        key=lambda item: float(item.get("confidence_score") or 0.0),
        reverse=True,
    )
    return deduplicated


def _finding_penalty(finding: Dict[str, Any]) -> float:
    severity = str(finding.get("severity") or "Info").strip().lower()
    confidence = float(finding.get("confidence_score") or 0.0)
    base = {
        "info": 2.0,
        "low": 8.0,
        "medium": 18.0,
        "high": 30.0,
    }.get(severity, 4.0)

    penalty = base * max(0.0, min(1.0, confidence))
    if bool(finding.get("stored_vulnerability_candidate")):
        penalty += 8.0
    return penalty


def _calculate_web_security_score(findings: List[Dict[str, Any]]) -> int:
    if not findings:
        return 100
    total_penalty = sum(_finding_penalty(item) for item in findings)
    score = max(0.0, 100.0 - total_penalty)
    return int(round(score))


def _empty_explanation(message: str) -> Dict[str, str]:
    return {
        "executive_summary": message,
        "technical_explanation": "Explanation unavailable.",
        "exploitation_scenario": "Not available.",
        "recommended_mitigation": "Review logs and retry explanation generation.",
    }


async def _attach_attack_explanations(
    findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    if not findings:
        return []

    openai_key_exists = _has_openai_api_key()
    ai_calls_attempted = 0
    results: List[Dict[str, Any]] = []

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        output = dict(finding)

        if not openai_key_exists:
            output["ai_explanation"] = _fallback_explanation_for_finding(
                output, reason="OPENAI_API_KEY missing"
            )
            results.append(output)
            continue

        if ai_calls_attempted >= MAX_AI_EXPLANATIONS_PER_SCAN:
            output["ai_explanation"] = _fallback_explanation_for_finding(
                output, reason=f"AI call cap reached ({MAX_AI_EXPLANATIONS_PER_SCAN})"
            )
            results.append(output)
            continue

        try:
            if ai_calls_attempted > 0:
                await asyncio.sleep(AI_EXPLANATION_MIN_INTERVAL_SECONDS)
            ai_calls_attempted += 1
            output["ai_explanation"] = await explain_attack_finding(output)
        except Exception as exc:
            output["ai_explanation"] = _fallback_explanation_for_finding(
                output, reason=f"LLM unavailable: {exc}"
            )

        results.append(output)

    return results


def _finding_to_pdf_vulnerability(finding: Dict[str, Any]) -> Dict[str, str]:
    vuln_type = str(finding.get("vulnerability_type") or "Potential vulnerability")
    parameter = str(finding.get("parameter") or "unknown")
    severity = str(finding.get("severity") or "Info")
    explanation = finding.get("ai_explanation") or {}
    recommended_fix = (
        str(explanation.get("recommended_mitigation") or "").strip()
        if isinstance(explanation, dict)
        else ""
    )
    if not recommended_fix:
        recommended_fix = "Validate inputs, encode outputs, and use least-privilege defaults."
    return {
        "issue": f"{vuln_type} on parameter {parameter}",
        "severity": severity,
        "recommended_fix": recommended_fix,
    }


def _web_response_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    output: List[Dict[str, Any]] = []
    for finding in findings:
        vulnerability_type = str(finding.get("vulnerability_type") or "Potential issue")
        taxonomy = get_vulnerability_taxonomy(vulnerability_type)
        output.append(
            {
                "target_url": str(finding.get("target_url") or ""),
                "parameter": str(finding.get("parameter") or ""),
                "payload": str(finding.get("payload") or ""),
                "payload_examples": finding.get("payload_examples") or [],
                "vulnerability_type": vulnerability_type,
                "owasp_category": taxonomy["owasp_category"],
                "cwe_id": taxonomy["cwe_id"],
                "severity": str(finding.get("severity") or "Info"),
                "confidence_score": float(finding.get("confidence_score") or 0.0),
                "stored_vulnerability_candidate": bool(
                    finding.get("stored_vulnerability_candidate")
                ),
                "ai_explanation": finding.get("ai_explanation"),
            }
        )
    return output


@app.get("/")
async def home():
    """Redirect root to the static frontend upload page."""
    return RedirectResponse(url="/static/index.html", status_code=302)


@app.post("/scan")
async def scan_endpoint(file: UploadFile = File(...), background_tasks: BackgroundTasks = None):
    try:
        content = await file.read()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Malformed input"
        ) from exc

    if not content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is empty"
        )

    try:
        code = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be UTF-8 encoded text",
        ) from exc

    # Use scanner module
    try:
        result = await scan_code(code)
    except Exception as exc:
        print(f"Scan error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to scan file",
        ) from exc

    report_data = {
        "type": "file",
        "filename": file.filename,
        "timestamp": result["timestamp"],
        "score": result["score"],
        "grade": result["grade"],
        "total_files": 1,
        "total_vulnerabilities": len(result["vulnerabilities"]),
        "vulnerabilities": result["vulnerabilities"],
    }

    # Persist and enqueue LLM enrichment in background
    reports_collection = await _get_reports_collection_or_503()

    try:
        insert_res = await reports_collection.insert_one(report_data)
        report_id = str(insert_res.inserted_id)
    except Exception as exc:
        print(f"Database insert error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        ) from exc

    # schedule LLM enrichment asynchronously (do not block response)
    if report_id and background_tasks is not None:
        background_tasks.add_task(_background_enrich, report_id, report_data["vulnerabilities"])
    elif report_id:
        # best-effort task
        try:
            import asyncio

            asyncio.create_task(_background_enrich(report_id, report_data["vulnerabilities"]))
        except Exception:
            pass

    response = {"security_score": result["score"], "grade": result["grade"], "vulnerabilities": result["vulnerabilities"]}
    if report_id:
        response["report_id"] = report_id
    return response


async def _background_enrich(report_id: str, vulnerabilities: list):
    try:
        enriched = await enrich_vulnerabilities(report_id, vulnerabilities)
    except Exception as exc:
        print(f"LLM enrichment task failed: {exc}")
        enriched = None

    if enriched is None:
        return

    # Save enrichment back to DB; be tolerant of errors
    try:
        reports_collection = await _get_reports_collection_or_503()
        await reports_collection.update_one({"_id": ObjectId(report_id)}, {"$set": {"llm": enriched}})
    except Exception as exc:
        print(f"Failed to save LLM enrichment: {exc}")


@app.post("/scan-repo")
async def scan_repo_endpoint(request: ScanRepoRequest, background_tasks: BackgroundTasks = None):
    """Scan a public GitHub repository for vulnerabilities.
    
    Returns aggregated vulnerabilities with file paths and line numbers.
    """
    repo_url = (request.repo_url or "").strip()
    if not repo_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="repo_url is required"
        )

    # Validate repo URL
    try:
        is_valid = await validate_github_url(repo_url)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid URL: {exc}"
        ) from exc

    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only public GitHub repositories are supported. Format: https://github.com/owner/repo"
        )

    # Download repo (async HTTP + threadpool file extraction inside utility)
    temp_dir = None
    try:
        temp_dir = await download_github_repo(repo_url)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    except Exception as exc:
        print(f"Failed to download repo: {exc}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to download repository: {exc}",
        ) from exc

    try:
        # Scan directory in threadpool (filesystem traversal is blocking)
        scan_result = await run_in_threadpool(scan_directory, temp_dir)
    except Exception as exc:
        print(f"Failed to scan repo: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to scan repository",
        ) from exc
    finally:
        if temp_dir:
            await run_in_threadpool(cleanup_temp_directory, temp_dir)

    # Persist report to database
    report_data = {
        "type": "repo",
        "repo_url": repo_url,
        "timestamp": scan_result["timestamp"],
        "score": scan_result["score"],
        "grade": scan_result["grade"],
        "total_files": scan_result["total_files"],
        "total_vulnerabilities": scan_result["total_vulnerabilities"],
        "vulnerabilities": scan_result["vulnerabilities"],
    }

    reports_collection = await _get_reports_collection_or_503()

    try:
        insert_res = await reports_collection.insert_one(report_data)
        report_id = str(insert_res.inserted_id)
    except Exception as exc:
        print(f"Database insert error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        ) from exc

    # Schedule LLM enrichment in background if enabled
    if report_id and background_tasks is not None:
        background_tasks.add_task(_background_enrich, report_id, report_data["vulnerabilities"])

    return {
        "repo_url": repo_url,
        "security_score": scan_result["score"],
        "grade": scan_result["grade"],
        "total_files_scanned": scan_result["total_files"],
        "total_vulnerabilities": scan_result["total_vulnerabilities"],
        "vulnerabilities": scan_result["vulnerabilities"],
        "report_id": report_id
    }


@app.post("/crawl")
async def crawl_endpoint(request: CrawlRequest):
    target_url = (request.target_url or "").strip()
    if not target_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="target_url is required",
        )

    try:
        return await crawl_site(target_url, max_depth=2)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        print(f"Crawl error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to crawl target URL",
        ) from exc


@app.post("/fuzz")
async def fuzz_endpoint(crawler_output: Dict[str, Any]):
    if not crawler_output:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Crawler output JSON is required",
        )

    try:
        return await fuzz_from_crawler_output(crawler_output)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        print(f"Fuzzing error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to execute fuzzing engine",
        ) from exc


@app.post("/scan-website")
async def scan_website_endpoint(request: ScanWebsiteRequest):
    target_url = (request.target_url or "").strip()
    if not target_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="target_url is required",
        )

    try:
        crawler_output = await crawl_site(target_url, max_depth=2)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        print(f"Crawl error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to crawl target URL",
        ) from exc

    try:
        fuzz_output = await fuzz_from_crawler_output(crawler_output)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        print(f"Fuzzing error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to execute fuzzing engine",
        ) from exc

    raw_findings = [
        item for item in (fuzz_output.get("findings") or []) if isinstance(item, dict)
    ]
    deduplicated_findings = _deduplicate_scan_findings(raw_findings)
    findings_with_explanations = await _attach_attack_explanations(deduplicated_findings)

    total_pages = int(
        crawler_output.get("pages_crawled")
        or len(crawler_output.get("pages") or [])
    )
    total_parameters = int(
        (crawler_output.get("summary") or {}).get("total_fuzz_parameters")
        or fuzz_output.get("total_parameters_received")
        or len(crawler_output.get("fuzz_parameters") or [])
    )
    total_findings = len(findings_with_explanations)
    stored_candidates = int(fuzz_output.get("stored_vulnerability_candidates") or 0)
    longest_parameter_chain = fuzz_output.get("longest_parameter_chain") or {}
    cross_page_reflections = fuzz_output.get("cross_page_reflections") or []

    security_score = _calculate_web_security_score(findings_with_explanations)
    grade = _web_grade_from_score(security_score)

    web_response_findings = _web_response_findings(findings_with_explanations)
    report_data = {
        "type": "web",
        "target_url": crawler_output.get("target_url") or target_url,
        "timestamp": datetime.utcnow(),
        "score": security_score,
        "grade": grade,
        "total_files": total_pages,
        "total_vulnerabilities": total_findings,
        "total_pages": total_pages,
        "total_parameters": total_parameters,
        "stored_vulnerability_candidates": stored_candidates,
        "longest_parameter_chain": longest_parameter_chain,
        "cross_page_reflections": cross_page_reflections,
        "findings": findings_with_explanations,
        "vulnerabilities": [
            _finding_to_pdf_vulnerability(item) for item in findings_with_explanations
        ],
        "crawl_output": crawler_output,
        "fuzz_output": fuzz_output,
    }

    reports_collection = await _get_reports_collection_or_503()
    try:
        insert_res = await reports_collection.insert_one(report_data)
        report_id = str(insert_res.inserted_id)
    except Exception as exc:
        print(f"Database insert error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        ) from exc

    try:
        await generate_pdf(report_data)
    except Exception as exc:
        print(f"PDF generation error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate PDF",
        ) from exc

    return {
        "report_id": report_id,
        "target_url": crawler_output.get("target_url") or target_url,
        "security_score": security_score,
        "grade": grade,
        "total_pages": total_pages,
        "total_parameters": total_parameters,
        "total_findings": total_findings,
        "stored_vulnerability_candidates": stored_candidates,
        "longest_parameter_chain": longest_parameter_chain,
        "cross_page_reflections": cross_page_reflections,
        "findings": web_response_findings,
    }


@app.post("/explain-attack", response_model=AttackExplanationResponse)
async def explain_attack_endpoint(payload: Dict[str, Any]):
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Fuzz finding JSON is required",
        )

    finding = payload.get("finding") if isinstance(payload.get("finding"), dict) else payload
    if not isinstance(finding, dict) or not finding:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provide a fuzz finding object (or {'finding': {...}}).",
        )

    try:
        explanation = await explain_attack_finding(finding)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except RuntimeError as exc:
        detail = str(exc) or "Failed to generate attack explanation"
        status_code = (
            status.HTTP_503_SERVICE_UNAVAILABLE
            if "GROQ_API_KEY" in detail
            else status.HTTP_502_BAD_GATEWAY
        )
        raise HTTPException(status_code=status_code, detail=detail) from exc
    except Exception as exc:
        print(f"Explain attack error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate attack explanation",
        ) from exc

    return AttackExplanationResponse(**explanation)


@app.get("/history")
async def get_history():
    # Fetch all reports
    reports_collection = await _get_reports_collection_or_503()

    try:
        docs = await reports_collection.find().sort("timestamp", -1).to_list(length=200)
    except Exception as exc:
        print(f"Database read error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to read from database",
        ) from exc

    return [_serialize_report(doc) for doc in docs]


@app.get("/history/{report_id}")
async def get_report(report_id: str):
    reports_collection = await _get_reports_collection_or_503()
    oid = _parse_object_id(report_id)

    try:
        doc = await reports_collection.find_one({"_id": oid})
    except Exception as exc:
        print(f"Database read error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to read from database",
        ) from exc

    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    return _serialize_report(doc)


@app.get("/report/{report_id}/pdf")
async def get_report_pdf(report_id: str):
    """Generate and return a PDF for a report."""
    reports_collection = await _get_reports_collection_or_503()
    oid = _parse_object_id(report_id)

    try:
        doc = await reports_collection.find_one({"_id": oid})
    except Exception as exc:
        print(f"Database read error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to read from database",
        ) from exc

    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    report = _serialize_report(doc)

    try:
        pdf_bytes = await generate_pdf(report)
    except Exception as exc:
        print(f"PDF generation error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate PDF",
        ) from exc

    if not pdf_bytes:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate PDF",
        )

    filename = f"report_{report_id}.pdf"

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
            "Cache-Control": "no-store",
        },
    )


@app.get("/test-db")
async def test_db():
    """Test DB connection and configuration."""
    if not MONGO_URI:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        )

    try:
        reports_collection = await _get_reports_collection_or_503()
        await reports_collection.database.command("ping")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"DB connection error: {exc}",
        ) from exc

    return {"collection": "reports", "db_type": str(type(reports_collection))}
