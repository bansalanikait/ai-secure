from io import BytesIO
from typing import Any, Dict

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


class ScanRepoRequest(BaseModel):
    repo_url: str


class CrawlRequest(BaseModel):
    target_url: str


class AttackExplanationResponse(BaseModel):
    executive_summary: str
    technical_explanation: str
    exploitation_scenario: str
    recommended_mitigation: str


app = FastAPI()

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
            if "OPENAI_API_KEY" in detail
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
