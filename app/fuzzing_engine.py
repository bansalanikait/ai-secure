import asyncio
import hashlib
import math
import re
import time
from itertools import combinations
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlparse, urlunparse

import httpx
from bs4 import BeautifulSoup
from sklearn.cluster import KMeans
from sklearn.ensemble import IsolationForest

from app.ai_reasoning import (
    AI_REASONING_ANOMALY_THRESHOLD,
    reason_on_anomaly,
    should_invoke_ai_reasoning,
)
from app.crawler import CRAWLER_USER_AGENT, MAX_REQUESTS_PER_SECOND
from app.flow_graph import FlowGraph, build_flow_graph_from_crawler_output

MAX_TOTAL_FUZZ_REQUESTS = 100
MAX_PAYLOADS_PER_PARAMETER = 10
MAX_COMBINATION_TESTS = 20
MAX_ERRORS_BEFORE_STOP = 15
REQUEST_TIMEOUT = httpx.Timeout(5.0, connect=5.0)
MIN_REQUEST_INTERVAL = 1.0 / max(1, MAX_REQUESTS_PER_SECOND)

LENGTH_DELTA_THRESHOLD = 120
LENGTH_DELTA_RATIO_THRESHOLD = 0.25
LEVENSHTEIN_THRESHOLD = 0.35
TIMING_RATIO_THRESHOLD = 2.0
TIMING_ABS_DELTA_MS = 400.0
MAX_EVIDENCE_SNIPPET_LEN = 220
MAX_TEXT_COMPARE = 900
ALLOWED_HTTP_METHODS = {"GET", "POST"}
ML_BLEND_RULE_WEIGHT = 0.7
ML_BLEND_ANOMALY_WEIGHT = 0.3
MIN_CLEAN_BASELINE_RESPONSES = 5
MAX_ESCALATION_TESTS = 3

HEADER_KEYS_FOR_DIFF = {
    "content-type",
    "content-security-policy",
    "server",
    "x-powered-by",
    "location",
    "set-cookie",
}
MAX_DOWNSTREAM_SCAN_PAGES = 5

BASE_PAYLOADS: Dict[str, List[str]] = {
    "sql_injection": [
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "'; SELECT 1--",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
    ],
    "path_traversal": [
        "../../etc/passwd",
        "..\\..\\Windows\\win.ini",
        "....//....//etc/passwd",
    ],
    "command_injection": [
        "; id",
        "&& whoami",
        "| cat /etc/passwd",
    ],
}

KNOWN_ERROR_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"sql syntax",
        r"syntax error",
        r"sqlite",
        r"postgres(?:ql)?",
        r"mysql",
        r"odbc",
        r"ora-\d+",
        r"traceback \(most recent call last\)",
        r"stack trace",
        r"exception",
        r"unhandled error",
        r"permission denied",
        r"file not found",
        r"directory traversal",
        r"command not found",
    ]
]

SQL_ERROR_PATTERNS_BY_DBMS: Dict[str, List[re.Pattern[str]]] = {
    "mysql": [
        re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
        re.compile(r"warning:\s*mysql_", re.IGNORECASE),
        re.compile(r"mysql_fetch_", re.IGNORECASE),
        re.compile(r"sqlstate\[\w+\]", re.IGNORECASE),
    ],
    "postgresql": [
        re.compile(r"pg_query\(\)", re.IGNORECASE),
        re.compile(r"postgresql.*error", re.IGNORECASE),
        re.compile(r"psql:\s*error", re.IGNORECASE),
        re.compile(r"syntax error at or near", re.IGNORECASE),
    ],
    "sqlite": [
        re.compile(r"sqlite error", re.IGNORECASE),
        re.compile(r"sqlite_exception", re.IGNORECASE),
        re.compile(r"sqlite3::", re.IGNORECASE),
        re.compile(r"near \".+\": syntax error", re.IGNORECASE),
    ],
    "mssql": [
        re.compile(r"microsoft sql server", re.IGNORECASE),
        re.compile(r"unclosed quotation mark after the character string", re.IGNORECASE),
        re.compile(r"sqlserverexception", re.IGNORECASE),
        re.compile(r"odbc sql server driver", re.IGNORECASE),
    ],
}

STACK_TRACE_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"traceback \(most recent call last\)",
        r"stack trace",
        r"exception",
        r"unhandled error",
    ]
]


class _AsyncRateLimiter:
    def __init__(self, min_interval_seconds: float) -> None:
        self.min_interval_seconds = max(0.0, float(min_interval_seconds))
        self._last_request_at = 0.0
        self._lock = asyncio.Lock()

    async def wait_turn(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request_at
            delay = self.min_interval_seconds - elapsed
            if self._last_request_at > 0 and delay > 0:
                await asyncio.sleep(delay)
            self._last_request_at = time.monotonic()


def _normalize_url(url: str) -> str:
    try:
        parsed = urlparse((url or "").strip())
    except Exception:
        return ""
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""

    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]

    port = parsed.port
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    else:
        netloc = host

    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")

    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query = urlencode(sorted(query_pairs), doseq=True) if query_pairs else ""
    return urlunparse((scheme, netloc, path, "", query, ""))


def _extract_fuzz_parameters(crawler_output: Dict[str, Any]) -> List[Dict[str, Any]]:
    collected: List[Dict[str, Any]] = []

    top_level = crawler_output.get("fuzz_parameters")
    if isinstance(top_level, list):
        collected.extend(item for item in top_level if isinstance(item, dict))

    pages = crawler_output.get("pages")
    if isinstance(pages, list):
        for page in pages:
            if not isinstance(page, dict):
                continue
            page_params = page.get("fuzz_parameters")
            if isinstance(page_params, list):
                collected.extend(item for item in page_params if isinstance(item, dict))

    deduped: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str, str, str, str]] = set()
    root_host = (
        urlparse(_normalize_url(str(crawler_output.get("target_url") or ""))).hostname or ""
    ).lower()

    for param in collected:
        name = str(param.get("name") or "").strip()
        location = str(param.get("location") or "query").strip().lower()
        method = str(param.get("method") or "GET").strip().upper()
        target_url = _normalize_url(str(param.get("target_url") or ""))
        source_url = _normalize_url(str(param.get("source_url") or target_url))
        input_type = str(param.get("input_type") or "").strip().lower()

        if not name or not target_url:
            continue
        if location not in {"query", "form"}:
            continue
        if method not in ALLOWED_HTTP_METHODS:
            method = "GET"

        target_host = (urlparse(target_url).hostname or "").lower()
        if root_host and target_host and target_host != root_host:
            continue

        example_values_raw = param.get("example_values") or []
        example_values = (
            [str(v) for v in example_values_raw if v is not None]
            if isinstance(example_values_raw, list)
            else [str(example_values_raw)]
        )

        signature = (name, location, method, target_url, input_type)
        if signature in seen:
            continue
        seen.add(signature)

        deduped.append(
            {
                "name": name,
                "location": location,
                "method": method,
                "target_url": target_url,
                "source_url": source_url,
                "required": bool(param.get("required")),
                "input_type": input_type or ("query" if location == "query" else "text"),
                "example_values": example_values,
            }
        )

    return deduped


def _url_encode(value: str) -> str:
    return quote(value, safe="")


def _double_url_encode(value: str) -> str:
    return quote(_url_encode(value), safe="")


def _case_variation(value: str) -> str:
    return "".join(ch.upper() if idx % 2 == 0 else ch.lower() for idx, ch in enumerate(value))


def _comment_variants(category: str, value: str) -> List[str]:
    variants: List[str] = []
    if category == "sql_injection":
        variants.append(f"{value}--")
        variants.append(value.replace(" ", "/**/"))
    elif category == "command_injection":
        variants.append(f"{value} #")
        variants.append(value.replace(" ", "${IFS}"))
    elif category == "xss":
        variants.append(f"<!--{value}-->")
        variants.append(value.replace("script", "scr<!--x-->ipt"))
    elif category == "path_traversal":
        variants.append(value.replace("../", "..//"))
        variants.append(value.replace("..\\", "..\\\\"))
    return variants


def _unique_keep_order(values: List[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _mutate_payloads() -> List[Tuple[str, str]]:
    per_category = _mutated_payload_pool()
    category_order = list(BASE_PAYLOADS.keys())
    pointers: Dict[str, int] = {category: 0 for category in category_order}
    payload_plan: List[Tuple[str, str]] = []

    # Round-robin keeps category diversity while capping total tests.
    while len(payload_plan) < MAX_PAYLOADS_PER_PARAMETER:
        progressed = False
        for category in category_order:
            idx = pointers[category]
            candidates = per_category.get(category, [])
            if idx >= len(candidates):
                continue
            payload_plan.append((category, candidates[idx]))
            pointers[category] += 1
            progressed = True
            if len(payload_plan) >= MAX_PAYLOADS_PER_PARAMETER:
                break
        if not progressed:
            break
    return payload_plan


def _mutated_payload_pool() -> Dict[str, List[str]]:
    per_category: Dict[str, List[str]] = {}
    for category, base_values in BASE_PAYLOADS.items():
        generated: List[str] = []
        for base in base_values:
            generated.append(base)
            generated.append(_url_encode(base))
            generated.append(_double_url_encode(base))
            generated.append(_case_variation(base))
            generated.extend(_comment_variants(category, base))
        per_category[category] = _unique_keep_order(generated)
    return per_category


def _payloads_for_category(
    category: str, exclude_payloads: Optional[Set[str]] = None
) -> List[str]:
    excluded = exclude_payloads or set()
    pool = _mutated_payload_pool().get(category, [])
    payloads: List[str] = []
    for payload in pool:
        if payload in excluded:
            continue
        payloads.append(payload)
        if len(payloads) >= MAX_ESCALATION_TESTS:
            break
    return payloads


def _detect_error_patterns(text: str) -> List[str]:
    body = text or ""
    matches: List[str] = []
    for pattern in KNOWN_ERROR_PATTERNS:
        match = pattern.search(body)
        if match:
            matches.append(match.group(0))
    return _unique_keep_order(matches)


def _detect_sql_error_contexts(text: str) -> List[Dict[str, str]]:
    body = text or ""
    contexts: List[Dict[str, str]] = []
    seen: Set[Tuple[str, str]] = set()
    for dbms, patterns in SQL_ERROR_PATTERNS_BY_DBMS.items():
        for pattern in patterns:
            match = pattern.search(body)
            if not match:
                continue
            signature = (dbms, match.group(0))
            if signature in seen:
                continue
            seen.add(signature)
            contexts.append({"dbms": dbms, "pattern": match.group(0)})
    return contexts


def _match_patterns(text: str, patterns: List[re.Pattern[str]]) -> List[str]:
    body = text or ""
    matches: List[str] = []
    for pattern in patterns:
        match = pattern.search(body)
        if match:
            matches.append(match.group(0))
    return _unique_keep_order(matches)


def _profile_error_pattern_count(profile: Dict[str, Any]) -> int:
    generic = {str(item) for item in (profile.get("error_patterns") or []) if item}
    stack = {str(item) for item in (profile.get("stack_trace_patterns") or []) if item}
    sql_ctx = {
        f"{str(item.get('dbms') or '')}:{str(item.get('pattern') or '')}"
        for item in (profile.get("sql_error_contexts") or [])
        if isinstance(item, dict)
    }
    return len(generic.union(stack).union(sql_ctx))


def _normalize_headers_map(headers: Any) -> Dict[str, str]:
    if not isinstance(headers, dict):
        return {}
    normalized: Dict[str, str] = {}
    for key, value in headers.items():
        k = str(key or "").strip().lower()
        if not k:
            continue
        normalized[k] = str(value or "").strip()
    return normalized


def _header_snapshot(headers: Dict[str, str]) -> Dict[str, str]:
    normalized = _normalize_headers_map(headers)
    snapshot: Dict[str, str] = {}
    for key in HEADER_KEYS_FOR_DIFF:
        value = normalized.get(key, "")
        if value:
            snapshot[key] = value
    return snapshot


def _header_diff_count(left: Dict[str, str], right: Dict[str, str]) -> int:
    a = _normalize_headers_map(left)
    b = _normalize_headers_map(right)
    all_keys = set(a.keys()).union(b.keys())
    diffs = 0
    for key in all_keys:
        if a.get(key, "") != b.get(key, ""):
            diffs += 1
    return diffs


def _server_banner_changed(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    return str(left.get("server_banner") or "").strip().lower() != str(
        right.get("server_banner") or ""
    ).strip().lower()


def _parameter_signature(parameter: Dict[str, Any]) -> Tuple[str, str, str, str]:
    return (
        str(parameter.get("name") or "").strip(),
        str(parameter.get("location") or "query").strip().lower(),
        str(parameter.get("method") or "GET").strip().upper(),
        str(parameter.get("target_url") or "").strip(),
    )


def _response_hash(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="ignore")).hexdigest()


def _content_kind(content_type: str, body: str) -> str:
    normalized = (content_type or "").strip().lower()
    if "html" in normalized:
        return "html"
    if "json" in normalized:
        return "json"
    # Body-shape fallback for loosely configured servers.
    stripped = (body or "").strip()
    if stripped.startswith("{") or stripped.startswith("["):
        return "json"
    if "<html" in stripped.lower() or "<body" in stripped.lower():
        return "html"
    return "other"


def _extract_html_reflection_context(payload: str, body: str) -> Dict[str, Any]:
    text = body or ""
    markers = _unique_keep_order(
        [marker for marker in [payload, unquote(payload)] if marker]
    )
    if not markers or not text:
        return {
            "in_script": False,
            "in_img": False,
            "in_a_href": False,
            "in_onclick": False,
            "unescaped_html": False,
        }

    soup = BeautifulSoup(text, "html.parser")
    in_script = False
    in_img = False
    in_a_href = False
    in_onclick = False
    unescaped_html = False

    for marker in markers:
        lower_marker = marker.lower()
        if not lower_marker:
            continue

        for script_tag in soup.find_all("script"):
            script_text = script_tag.get_text(separator=" ", strip=False) or ""
            script_raw = str(script_tag)
            if lower_marker in script_text.lower() or lower_marker in script_raw.lower():
                in_script = True

        for img_tag in soup.find_all("img"):
            for attr_val in img_tag.attrs.values():
                attr_text = " ".join(attr_val) if isinstance(attr_val, list) else str(attr_val)
                if lower_marker in attr_text.lower():
                    in_img = True

        for anchor in soup.find_all("a"):
            href = str(anchor.get("href") or "")
            if lower_marker in href.lower():
                in_a_href = True

        for tag in soup.find_all(True):
            onclick = str(tag.get("onclick") or "")
            if lower_marker in onclick.lower():
                in_onclick = True

        if any(ch in marker for ch in ["<", ">", "\"", "'"]) and marker in text:
            unescaped_html = True

    return {
        "in_script": in_script,
        "in_img": in_img,
        "in_a_href": in_a_href,
        "in_onclick": in_onclick,
        "unescaped_html": unescaped_html,
    }


def _profile_response(response: Dict[str, Any]) -> Dict[str, Any]:
    body = str(response.get("body") or "")
    content_type = str(response.get("content_type") or "").strip().lower()
    headers = _header_snapshot(_normalize_headers_map(response.get("headers") or {}))
    server_banner = str(headers.get("server") or "").strip()
    redirect_occurred = bool(response.get("redirect_occurred"))
    csp_present = bool(headers.get("content-security-policy"))
    return {
        "status_code": int(response.get("status_code", 0)),
        "response_length": int(response.get("length", 0)),
        "response_time_ms": float(response.get("response_time_ms", 0.0)),
        "response_hash": _response_hash(body),
        "content_type": content_type,
        "content_kind": _content_kind(content_type, body),
        "headers": headers,
        "redirect_occurred": redirect_occurred,
        "csp_present": csp_present,
        "server_banner": server_banner,
        "error_patterns": _detect_error_patterns(body),
        "sql_error_contexts": _detect_sql_error_contexts(body),
        "stack_trace_patterns": _match_patterns(body, STACK_TRACE_PATTERNS),
    }


def _median(values: List[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2 == 1:
        return float(ordered[mid])
    return float((ordered[mid - 1] + ordered[mid]) / 2.0)


def _build_baseline_feature_rows(
    baseline_profiles: List[Dict[str, Any]]
) -> Tuple[List[List[float]], Dict[str, float]]:
    profs = [item.get("profile", {}) for item in baseline_profiles if isinstance(item, dict)]
    lengths = [float(p.get("response_length", 0.0)) for p in profs]
    times = [float(p.get("response_time_ms", 0.0)) for p in profs]
    length_center = _median(lengths)
    time_center = _median(times)

    reference_headers: Dict[str, str] = {}
    reference_server = ""
    if profs:
        reference_headers = _normalize_headers_map(profs[0].get("headers") or {})
        reference_server = str(profs[0].get("server_banner") or "").strip()

    rows: List[List[float]] = []
    for profile in profs:
        status_code = float(profile.get("status_code", 0.0))
        length_delta = abs(float(profile.get("response_length", 0.0)) - length_center)
        time_delta = abs(float(profile.get("response_time_ms", 0.0)) - time_center)
        reflection_flag = 0.0
        error_pattern_count = float(_profile_error_pattern_count(profile))
        header_diff_count = float(
            _header_diff_count(reference_headers, _normalize_headers_map(profile.get("headers") or {}))
        )
        redirect_occurrence = 1.0 if bool(profile.get("redirect_occurred")) else 0.0
        csp_presence = 1.0 if bool(profile.get("csp_present")) else 0.0
        server_banner_change = (
            1.0
            if str(profile.get("server_banner") or "").strip().lower()
            != reference_server.lower()
            else 0.0
        )
        rows.append(
            [
                status_code,
                length_delta,
                time_delta,
                reflection_flag,
                error_pattern_count,
                header_diff_count,
                redirect_occurrence,
                csp_presence,
                server_banner_change,
            ]
        )

    return rows, {
        "length_center": length_center,
        "time_center": time_center,
        "reference_header_count": float(len(reference_headers)),
    }


def _cluster_clean_baselines(
    baseline_profiles: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    if len(baseline_profiles) < MIN_CLEAN_BASELINE_RESPONSES:
        return baseline_profiles, {"clustered": False, "clusters": 0}

    feature_rows, _ = _build_baseline_feature_rows(baseline_profiles)
    if len(feature_rows) < MIN_CLEAN_BASELINE_RESPONSES:
        return baseline_profiles, {"clustered": False, "clusters": 0}

    n_clusters = min(2, len(feature_rows))
    try:
        clustering = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
        labels = clustering.fit_predict(feature_rows)
    except Exception:
        return baseline_profiles, {"clustered": False, "clusters": 0}

    counts: Dict[int, int] = {}
    for label in labels:
        counts[int(label)] = counts.get(int(label), 0) + 1

    dominant_label = max(counts.keys(), key=lambda label: counts[label])
    clustered = [
        baseline_profiles[idx]
        for idx, label in enumerate(labels)
        if int(label) == int(dominant_label)
    ]
    if len(clustered) < 2:
        clustered = baseline_profiles

    return clustered, {
        "clustered": True,
        "clusters": n_clusters,
        "dominant_cluster_size": len(clustered),
    }


def _train_anomaly_model(
    baseline_profiles: List[Dict[str, Any]]
) -> Tuple[Optional[IsolationForest], Dict[str, Any]]:
    feature_rows, stats = _build_baseline_feature_rows(baseline_profiles)
    if len(feature_rows) < 2:
        return None, stats
    model = IsolationForest(
        n_estimators=100,
        contamination="auto",
        random_state=42,
    )
    model.fit(feature_rows)
    return model, stats


def _build_fuzz_feature_row(
    baseline_profile: Dict[str, Any],
    mutated_profile: Dict[str, Any],
    signals: Dict[str, Any],
) -> List[float]:
    status_code = float(mutated_profile.get("status_code", 0.0))
    response_length_delta = abs(
        float(mutated_profile.get("response_length", 0.0))
        - float(baseline_profile.get("response_length", 0.0))
    )
    response_time_delta = abs(
        float(mutated_profile.get("response_time_ms", 0.0))
        - float(baseline_profile.get("response_time_ms", 0.0))
    )
    reflection_flag = 1.0 if signals.get("reflection_detected") else 0.0
    error_pattern_count = float(_profile_error_pattern_count(mutated_profile))
    header_diff_count = float(
        _header_diff_count(
            _normalize_headers_map(baseline_profile.get("headers") or {}),
            _normalize_headers_map(mutated_profile.get("headers") or {}),
        )
    )
    redirect_occurrence = 1.0 if bool(mutated_profile.get("redirect_occurred")) else 0.0
    csp_presence = 1.0 if bool(mutated_profile.get("csp_present")) else 0.0
    server_banner_change = (
        1.0 if _server_banner_changed(baseline_profile, mutated_profile) else 0.0
    )
    return [
        status_code,
        response_length_delta,
        response_time_delta,
        reflection_flag,
        error_pattern_count,
        header_diff_count,
        redirect_occurrence,
        csp_presence,
        server_banner_change,
    ]


def _ml_anomaly_score(model: Optional[IsolationForest], feature_row: List[float]) -> float:
    if model is None:
        return 0.0
    raw_score = float(model.decision_function([feature_row])[0])
    # Convert IsolationForest decision score to anomaly-likelihood in [0,1].
    # Positive means normal; negative means anomalous.
    anomaly = 1.0 / (1.0 + math.exp(6.0 * raw_score))
    if anomaly < 0.0:
        anomaly = 0.0
    if anomaly > 1.0:
        anomaly = 1.0
    return round(anomaly, 4)


def _bounded_text(value: str) -> str:
    return (value or "")[:MAX_TEXT_COMPARE]


def _levenshtein_ratio(left: str, right: str) -> float:
    a = _bounded_text(left)
    b = _bounded_text(right)
    if a == b:
        return 0.0
    if not a:
        return 1.0 if b else 0.0
    if not b:
        return 1.0

    prev = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i]
        for j, char_b in enumerate(b, start=1):
            insert_cost = current[j - 1] + 1
            delete_cost = prev[j] + 1
            replace_cost = prev[j - 1] + (char_a != char_b)
            current.append(min(insert_cost, delete_cost, replace_cost))
        prev = current
    distance = prev[-1]
    return distance / float(max(len(a), len(b)))


def _reflection_detected(payload: str, body: str) -> bool:
    if not payload:
        return False
    text = body or ""
    if payload in text:
        return True
    decoded = unquote(payload)
    if decoded and decoded in text:
        return True
    return False


def _make_evidence_snippet(text: str, marker: str) -> str:
    body = text or ""
    if not body:
        return ""
    idx = body.lower().find((marker or "").lower())
    if idx < 0:
        return body[:MAX_EVIDENCE_SNIPPET_LEN]
    left = max(0, idx - 80)
    right = min(len(body), idx + len(marker) + 80)
    return body[left:right][:MAX_EVIDENCE_SNIPPET_LEN]


def _compute_signals(
    payload: str,
    baseline: Dict[str, Any],
    baseline_profile: Dict[str, Any],
    mutated: Dict[str, Any],
    mutated_profile: Dict[str, Any],
) -> Dict[str, Any]:
    baseline_status = int(baseline_profile["status_code"])
    mutated_status = int(mutated_profile["status_code"])
    baseline_length = int(baseline_profile["response_length"])
    mutated_length = int(mutated_profile["response_length"])
    length_delta = abs(mutated_length - baseline_length)

    length_ratio = 1.0 if baseline_length == 0 and mutated_length > 0 else (
        (length_delta / baseline_length) if baseline_length > 0 else 0.0
    )
    size_anomaly = (
        length_delta >= LENGTH_DELTA_THRESHOLD
        or length_ratio >= LENGTH_DELTA_RATIO_THRESHOLD
    )
    status_change = baseline_status != mutated_status

    text_diff_ratio = _levenshtein_ratio(
        str(baseline.get("body") or ""),
        str(mutated.get("body") or ""),
    )

    reflection_detected = _reflection_detected(payload, str(mutated.get("body") or ""))
    baseline_errors = set(baseline_profile.get("error_patterns") or [])
    mutated_errors = set(mutated_profile.get("error_patterns") or [])
    new_error_patterns = sorted(mutated_errors.difference(baseline_errors))
    baseline_sql_errors = {
        (str(item.get("dbms") or ""), str(item.get("pattern") or ""))
        for item in (baseline_profile.get("sql_error_contexts") or [])
        if isinstance(item, dict)
    }
    mutated_sql_errors = {
        (str(item.get("dbms") or ""), str(item.get("pattern") or ""))
        for item in (mutated_profile.get("sql_error_contexts") or [])
        if isinstance(item, dict)
    }
    sql_error_detected = bool(mutated_sql_errors.difference(baseline_sql_errors))
    baseline_stack_traces = set(baseline_profile.get("stack_trace_patterns") or [])
    mutated_stack_traces = set(mutated_profile.get("stack_trace_patterns") or [])
    stack_trace_detected = bool(mutated_stack_traces.difference(baseline_stack_traces))
    error_pattern_detected = bool(sql_error_detected or stack_trace_detected)

    baseline_time = float(baseline_profile["response_time_ms"])
    mutated_time = float(mutated_profile["response_time_ms"])
    timing_anomaly = bool(
        baseline_time > 0 and mutated_time >= baseline_time * TIMING_RATIO_THRESHOLD
    )
    baseline_content_type = str(baseline_profile.get("content_type") or "")
    mutated_content_type = str(mutated_profile.get("content_type") or "")
    content_type_changed = bool(
        baseline_content_type
        and mutated_content_type
        and baseline_content_type != mutated_content_type
    )
    header_diff_count = _header_diff_count(
        _normalize_headers_map(baseline_profile.get("headers") or {}),
        _normalize_headers_map(mutated_profile.get("headers") or {}),
    )
    redirect_occurred = bool(mutated_profile.get("redirect_occurred"))
    csp_present = bool(mutated_profile.get("csp_present"))
    server_banner_changed = _server_banner_changed(baseline_profile, mutated_profile)
    response_content_kind = str(mutated_profile.get("content_kind") or "other")
    html_context = _extract_html_reflection_context(
        payload,
        str(mutated.get("body") or ""),
    ) if response_content_kind == "html" else {
        "in_script": False,
        "in_img": False,
        "in_a_href": False,
        "in_onclick": False,
        "unescaped_html": False,
    }
    xss_dom_context_detected = bool(
        html_context["in_script"]
        or html_context["in_img"]
        or html_context["in_a_href"]
        or html_context["in_onclick"]
    )
    xss_unescaped_html = bool(html_context["unescaped_html"])
    levenshtein_signal = text_diff_ratio >= LEVENSHTEIN_THRESHOLD

    return {
        "status_change": status_change,
        "length_delta": int(length_delta),
        "length_anomaly": size_anomaly,
        "levenshtein_diff": round(text_diff_ratio, 4),
        "levenshtein_signal": bool(levenshtein_signal),
        "reflection_detected": reflection_detected,
        "error_pattern_detected": error_pattern_detected,
        "sql_error_detected": sql_error_detected,
        "stack_trace_detected": stack_trace_detected,
        "new_error_patterns": new_error_patterns,
        "timing_anomaly": timing_anomaly,
        "content_type_changed": content_type_changed,
        "header_diff_count": int(header_diff_count),
        "redirect_occurred": redirect_occurred,
        "csp_present": csp_present,
        "server_banner_changed": server_banner_changed,
        "response_content_kind": response_content_kind,
        "xss_dom_context_detected": xss_dom_context_detected,
        "xss_unescaped_html": xss_unescaped_html,
        "xss_dom_context": html_context,
    }


def _confidence_score(signals: Dict[str, Any]) -> float:
    # Weighted scoring model (requested):
    # reflection=+0.1, length_delta=+0.1, levenshtein_diff=+0.1,
    # error_pattern=+0.4, status_change=+0.3, timing_anomaly=+0.3
    # Plus content-type anomaly as an additional strong signal.
    score = 0.0
    reflection_weight = 0.1
    if signals["response_content_kind"] == "json":
        reflection_weight = reflection_weight * 0.5
    if signals["reflection_detected"]:
        score += reflection_weight
    if signals["length_anomaly"]:
        score += 0.1
    if signals["levenshtein_signal"]:
        score += 0.1
    if signals["error_pattern_detected"]:
        score += 0.4
    if signals["status_change"]:
        score += 0.3
    if signals["timing_anomaly"]:
        score += 0.3
    if signals["content_type_changed"]:
        score += 0.2
    if signals["xss_dom_context_detected"]:
        score += 0.05
    if signals["xss_unescaped_html"]:
        score += 0.10

    strong_signal_present = bool(
        signals["status_change"]
        or signals["sql_error_detected"]
        or signals["stack_trace_detected"]
        or signals["timing_anomaly"]
        or signals["content_type_changed"]
    )

    # Confidence should not rise meaningfully without strong backend-side signals.
    if not strong_signal_present:
        cap_without_strong = 0.39
        if signals["xss_unescaped_html"] or signals["xss_dom_context_detected"]:
            cap_without_strong = 0.6
        score = min(score, cap_without_strong)

    # Reflection-only must not exceed Low severity.
    if signals["reflection_detected"] and not (
        signals["status_change"]
        or signals["error_pattern_detected"]
        or signals["timing_anomaly"]
        or signals["content_type_changed"]
    ):
        score = min(score, 0.6)

    if score > 1.0:
        score = 1.0
    return round(score, 4)


def _combine_confidence(rule_confidence: float, anomaly_score: float) -> float:
    combined = (rule_confidence * ML_BLEND_RULE_WEIGHT) + (
        anomaly_score * ML_BLEND_ANOMALY_WEIGHT
    )
    if combined < 0.0:
        combined = 0.0
    if combined > 1.0:
        combined = 1.0
    return round(combined, 4)


def _severity_from_confidence(confidence: float) -> str:
    if confidence < 0.4:
        return "Info"
    if confidence <= 0.6:
        return "Low"
    if confidence <= 0.8:
        return "Medium"
    return "High"


def _map_vulnerability_type(category: str, signals: Dict[str, Any]) -> str:
    if category == "sql_injection":
        return "sql_injection_possible" if signals["error_pattern_detected"] else "sql_injection_suspected"
    if category == "xss":
        return "xss_reflection_possible" if signals["reflection_detected"] else "xss_suspected"
    if category == "path_traversal":
        if signals["error_pattern_detected"] or signals["status_change"]:
            return "path_traversal_possible"
        return "path_traversal_suspected"
    if category == "command_injection":
        if signals["timing_anomaly"] or signals["error_pattern_detected"]:
            return "command_injection_possible"
        return "command_injection_suspected"
    return f"{category}_suspected"


def _build_request_for_assignments(
    assignments: List[Tuple[Dict[str, Any], str]]
) -> Tuple[str, str, Optional[Dict[str, str]], Optional[Dict[str, str]]]:
    first = assignments[0][0]
    method = str(first.get("method") or "GET").upper()
    if method not in ALLOWED_HTTP_METHODS:
        method = "GET"

    parsed = urlparse(str(first.get("target_url") or ""))
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query_dict: Dict[str, str] = {k: v for k, v in query_pairs}
    form_data: Dict[str, str] = {}

    for parameter, value in assignments:
        name = str(parameter.get("name") or "")
        location = str(parameter.get("location") or "query").lower()
        current_method = str(parameter.get("method") or method).upper()

        if location == "query" or current_method == "GET":
            query_dict[name] = value
        else:
            form_data[name] = value

    url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
    params = query_dict if query_dict else None
    data = form_data if form_data else None
    return method, url, params, data


async def _send_request(
    client: httpx.AsyncClient,
    limiter: _AsyncRateLimiter,
    method: str,
    url: str,
    params: Optional[Dict[str, str]],
    data: Optional[Dict[str, str]],
) -> Dict[str, Any]:
    await limiter.wait_turn()
    started = time.perf_counter()
    try:
        response = await client.request(
            method,
            url,
            params=params,
            data=data,
            headers={"X-Safe-Fuzz": "true"},
        )
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        body = response.text or ""
        return {
            "status_code": int(response.status_code),
            "body": body,
            "length": len(body),
            "response_time_ms": round(elapsed_ms, 2),
            "content_type": str(response.headers.get("content-type") or "").split(";")[0].strip().lower(),
            "headers": dict(response.headers),
            "redirect_occurred": bool(response.history) or (300 <= int(response.status_code) < 400),
            "error": "",
        }
    except httpx.HTTPError as exc:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return {
            "status_code": 0,
            "body": "",
            "length": 0,
            "response_time_ms": round(elapsed_ms, 2),
            "content_type": "",
            "headers": {},
            "redirect_occurred": False,
            "error": str(exc),
        }


def _longest_parameter_chain(flow_graph: FlowGraph, parameters: List[Dict[str, Any]]) -> Dict[str, Any]:
    longest = {"parameter": "", "hops": 0, "path": []}
    seen: Set[str] = set()
    for parameter in parameters:
        name = str(parameter.get("name") or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        for item in flow_graph.get_parameter_paths(name):
            hops = int(item.get("hops") or 0)
            if hops <= int(longest.get("hops") or 0):
                continue
            longest = {
                "parameter": name,
                "hops": hops,
                "path": list(item.get("path") or []),
            }
    return longest


async def _scan_downstream_for_payload_marker(
    client: httpx.AsyncClient,
    limiter: _AsyncRateLimiter,
    flow_graph: FlowGraph,
    source_url: str,
    parameter_names: List[str],
    payload_marker: str,
    safe_request_cap: int,
    total_requests: int,
    total_errors: int,
) -> Dict[str, Any]:
    source = str(source_url or "").strip()
    marker = str(payload_marker or "")
    if not source or not marker:
        return {
            "detections": [],
            "flow_chains": [],
            "requests_used": 0,
            "errors_used": 0,
        }

    downstream_nodes = flow_graph.get_downstream_nodes(source)
    if not downstream_nodes:
        return {
            "detections": [],
            "flow_chains": [],
            "requests_used": 0,
            "errors_used": 0,
        }

    marker_decoded = unquote(marker)
    requests_used = 0
    errors_used = 0
    detections: List[Dict[str, Any]] = []
    flow_chains: List[Dict[str, Any]] = []
    seen_sink: Set[str] = set()

    for downstream_url in downstream_nodes[:MAX_DOWNSTREAM_SCAN_PAGES]:
        if total_requests + requests_used >= safe_request_cap:
            break
        if total_errors + errors_used >= MAX_ERRORS_BEFORE_STOP:
            break

        response = await _send_request(
            client=client,
            limiter=limiter,
            method="GET",
            url=downstream_url,
            params=None,
            data=None,
        )
        requests_used += 1
        if response.get("error"):
            errors_used += 1
            continue

        body = str(response.get("body") or "")
        reflected = bool(
            marker and marker in body
            or (marker_decoded and marker_decoded in body)
        )
        if not reflected:
            continue
        if downstream_url in seen_sink:
            continue
        seen_sink.add(downstream_url)

        chain: List[str] = flow_graph.shortest_path(source, downstream_url)
        if not chain:
            chain = [source, downstream_url]
        flow_chains.append(
            {
                "source": source,
                "sink": downstream_url,
                "path": chain,
                "hops": max(0, len(chain) - 1),
            }
        )
        detections.append(
            {
                "source": source,
                "sink": downstream_url,
                "parameter_names": parameter_names,
                "response_status": int(response.get("status_code") or 0),
                "response_time_ms": float(response.get("response_time_ms") or 0.0),
            }
        )

    return {
        "detections": detections,
        "flow_chains": flow_chains,
        "requests_used": requests_used,
        "errors_used": errors_used,
    }


def _generate_parameter_pairs(parameters: List[Dict[str, Any]]) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
    grouped: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
    for parameter in parameters:
        key = (
            str(parameter.get("target_url") or ""),
            str(parameter.get("method") or "GET").upper(),
            str(parameter.get("location") or "query").lower(),
        )
        grouped.setdefault(key, []).append(parameter)

    pairs: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
    for group in grouped.values():
        for left, right in combinations(group, 2):
            if left.get("name") == right.get("name"):
                continue
            pairs.append((left, right))
            if len(pairs) >= MAX_COMBINATION_TESTS:
                return pairs
    return pairs


def _format_parameter_label(assignments: List[Tuple[Dict[str, Any], str]]) -> str:
    names = sorted(str(param.get("name") or "") for param, _ in assignments)
    return ",".join(name for name in names if name)


def _build_finding(
    url: str,
    parameter_label: str,
    payload: str,
    category: str,
    signals: Dict[str, Any],
    mutated: Dict[str, Any],
    ml_anomaly_score: float,
) -> Dict[str, Any]:
    rule_confidence = _confidence_score(signals)
    confidence = _combine_confidence(rule_confidence, ml_anomaly_score)
    marker = payload
    if signals["new_error_patterns"]:
        marker = signals["new_error_patterns"][0]
    evidence = _make_evidence_snippet(str(mutated.get("body") or ""), marker)
    if not evidence and mutated.get("error"):
        evidence = str(mutated.get("error"))[:MAX_EVIDENCE_SNIPPET_LEN]
    if not evidence:
        evidence = (
            f"status_change={signals['status_change']}, length_delta={signals['length_delta']}, "
            f"timing_anomaly={signals['timing_anomaly']}"
        )

    return {
        "target_url": url,
        "parameter": parameter_label,
        "payload": payload,
        "vulnerability_type": _map_vulnerability_type(category, signals),
        "severity": _severity_from_confidence(confidence),
        "confidence_score": confidence,
        "rule_confidence_score": rule_confidence,
        "ml_anomaly_score": ml_anomaly_score,
        "stored_vulnerability_candidate": False,
        "flow_chain_evidence": [],
        "evidence_snippet": evidence,
        "detection_signals": {
            "status_change": bool(signals["status_change"]),
            "length_delta": int(signals["length_delta"]),
            "reflection_detected": bool(signals["reflection_detected"]),
            "error_pattern_detected": bool(signals["error_pattern_detected"]),
            "sql_error_detected": bool(signals["sql_error_detected"]),
            "stack_trace_detected": bool(signals["stack_trace_detected"]),
            "timing_anomaly": bool(signals["timing_anomaly"]),
            "content_type_changed": bool(signals["content_type_changed"]),
            "header_diff_count": int(signals.get("header_diff_count", 0)),
            "redirect_occurred": bool(signals.get("redirect_occurred")),
            "csp_present": bool(signals.get("csp_present")),
            "server_banner_changed": bool(signals.get("server_banner_changed")),
            "response_content_kind": str(signals["response_content_kind"]),
            "xss_dom_context_detected": bool(signals["xss_dom_context_detected"]),
            "xss_unescaped_html": bool(signals["xss_unescaped_html"]),
            "xss_dom_context": dict(signals.get("xss_dom_context") or {}),
            "levenshtein_diff": float(signals["levenshtein_diff"]),
        },
    }


def _should_emit_finding(signals: Dict[str, Any]) -> bool:
    json_reflection_only = bool(
        str(signals.get("response_content_kind") or "") == "json"
        and bool(signals.get("reflection_detected"))
        and not bool(signals.get("status_change"))
        and not bool(signals.get("error_pattern_detected"))
        and not bool(signals.get("timing_anomaly"))
        and not bool(signals.get("content_type_changed"))
        and not bool(signals.get("length_anomaly"))
        and not bool(signals.get("xss_dom_context_detected"))
        and not bool(signals.get("xss_unescaped_html"))
        and float(signals.get("levenshtein_diff", 0.0)) < LEVENSHTEIN_THRESHOLD
    )
    if json_reflection_only:
        return False

    return bool(
        signals["status_change"]
        or signals["length_anomaly"]
        or signals["reflection_detected"]
        or signals["error_pattern_detected"]
        or signals["timing_anomaly"]
        or signals["content_type_changed"]
        or signals["xss_dom_context_detected"]
        or signals["xss_unescaped_html"]
        or float(signals["levenshtein_diff"]) >= LEVENSHTEIN_THRESHOLD
    )


async def fuzz_from_crawler_output(
    crawler_output: Dict[str, Any], max_requests: int = MAX_TOTAL_FUZZ_REQUESTS
) -> Dict[str, Any]:
    if not isinstance(crawler_output, dict):
        raise ValueError("Crawler output JSON object is required.")

    target_url = _normalize_url(str(crawler_output.get("target_url") or ""))
    if not target_url:
        raise ValueError("Crawler output must include a valid target_url.")

    parameters = _extract_fuzz_parameters(crawler_output)
    if not parameters:
        raise ValueError("No fuzz_parameters found in crawler output.")
    flow_graph = build_flow_graph_from_crawler_output(crawler_output)
    longest_parameter_chain = _longest_parameter_chain(flow_graph, parameters)

    safe_request_cap = max(1, min(int(max_requests), MAX_TOTAL_FUZZ_REQUESTS))
    payload_plan = _mutate_payloads()
    combo_payload_plan = payload_plan[: min(4, len(payload_plan))]
    parameter_pairs = _generate_parameter_pairs(parameters)

    findings: List[Dict[str, Any]] = []
    finding_candidates: List[Dict[str, Any]] = []
    baseline_profiles: List[Dict[str, Any]] = []
    clean_baseline_profiles: List[Dict[str, Any]] = []
    baseline_cache: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}
    limiter = _AsyncRateLimiter(MIN_REQUEST_INTERVAL)

    total_requests = 0
    total_errors = 0
    stop_reason = ""
    ai_reasoning_attempted = 0
    ai_reasoning_applied = 0
    anomaly_model: Optional[IsolationForest] = None
    anomaly_stats: Dict[str, Any] = {"length_center": 0.0, "time_center": 0.0}
    anomaly_cluster_info: Dict[str, Any] = {"clustered": False, "clusters": 0}
    anomaly_model_enabled = True
    flow_chains_detected: List[Dict[str, Any]] = []
    cross_page_reflections: List[Dict[str, Any]] = []
    stored_vulnerability_candidates = 0

    async with httpx.AsyncClient(
        timeout=REQUEST_TIMEOUT,
        follow_redirects=True,
        headers={"User-Agent": CRAWLER_USER_AGENT},
    ) as client:
        # Pre-fuzz clean baseline collection: gather at least 5 clean responses.
        preflight_attempts = 0
        max_preflight_attempts = max(MIN_CLEAN_BASELINE_RESPONSES * 3, len(parameters) * 3)
        while (
            len(clean_baseline_profiles) < MIN_CLEAN_BASELINE_RESPONSES
            and preflight_attempts < max_preflight_attempts
            and total_requests < safe_request_cap
            and total_errors < MAX_ERRORS_BEFORE_STOP
        ):
            parameter = parameters[preflight_attempts % len(parameters)]
            preflight_attempts += 1
            baseline_value = parameter["example_values"][0] if parameter.get("example_values") else "1"
            baseline_assignments = [(parameter, baseline_value)]
            method, url, params, data = _build_request_for_assignments(baseline_assignments)
            baseline_response = await _send_request(client, limiter, method, url, params, data)
            total_requests += 1
            if baseline_response.get("error"):
                total_errors += 1

            baseline_profile = _profile_response(baseline_response)
            entry = {
                "target_url": url,
                "parameter": str(parameter.get("name") or ""),
                "profile": baseline_profile,
            }
            baseline_profiles.append(entry)

            sig = _parameter_signature(parameter)
            baseline_cache[sig] = {
                "response": baseline_response,
                "profile": baseline_profile,
                "parameter": parameter,
            }

            if (not baseline_response.get("error")) and int(baseline_response.get("status_code", 0)) < 500:
                clean_baseline_profiles.append(entry)

        if len(clean_baseline_profiles) < MIN_CLEAN_BASELINE_RESPONSES:
            stop_reason = "insufficient_clean_baselines"
        else:
            clustered_clean, anomaly_cluster_info = _cluster_clean_baselines(clean_baseline_profiles)
            anomaly_model, anomaly_stats = _train_anomaly_model(clustered_clean)

        # Single-parameter fuzzing
        if not stop_reason:
            for parameter in parameters:
                if total_requests >= safe_request_cap:
                    stop_reason = "request_cap_reached"
                    break
                if total_errors >= MAX_ERRORS_BEFORE_STOP:
                    stop_reason = "too_many_request_errors"
                    break

                sig = _parameter_signature(parameter)
                cached = baseline_cache.get(sig)
                if cached is not None:
                    baseline_response = dict(cached.get("response") or {})
                    baseline_profile = dict(cached.get("profile") or {})
                else:
                    baseline_value = parameter["example_values"][0] if parameter.get("example_values") else "1"
                    baseline_assignments = [(parameter, baseline_value)]
                    method, url, params, data = _build_request_for_assignments(baseline_assignments)
                    baseline_response = await _send_request(client, limiter, method, url, params, data)
                    total_requests += 1
                    if baseline_response.get("error"):
                        total_errors += 1
                    baseline_profile = _profile_response(baseline_response)
                    baseline_profiles.append(
                        {
                            "target_url": url,
                            "parameter": str(parameter.get("name") or ""),
                            "profile": baseline_profile,
                        }
                    )
                    baseline_cache[sig] = {
                        "response": baseline_response,
                        "profile": baseline_profile,
                        "parameter": parameter,
                    }

                for category, payload in payload_plan:
                    if total_requests >= safe_request_cap:
                        stop_reason = "request_cap_reached"
                        break
                    if total_errors >= MAX_ERRORS_BEFORE_STOP:
                        stop_reason = "too_many_request_errors"
                        break

                    assignments = [(parameter, payload)]
                    method, url, params, data = _build_request_for_assignments(assignments)
                    mutated_response = await _send_request(client, limiter, method, url, params, data)
                    total_requests += 1
                    if mutated_response.get("error"):
                        total_errors += 1

                    mutated_profile = _profile_response(mutated_response)
                    signals = _compute_signals(
                        payload,
                        baseline_response,
                        baseline_profile,
                        mutated_response,
                        mutated_profile,
                    )
                    if not _should_emit_finding(signals):
                        continue
                    finding_candidates.append(
                        {
                            "url": str(parameter.get("target_url") or ""),
                            "parameter_label": str(parameter.get("name") or ""),
                            "payload": payload,
                            "category": category,
                            "parameters": [parameter],
                            "baseline_response": baseline_response,
                            "signals": signals,
                            "mutated_response": mutated_response,
                            "baseline_profile": baseline_profile,
                            "mutated_profile": mutated_profile,
                        }
                    )

                if stop_reason:
                    break

        # Two-parameter combination fuzzing (capped)
        if not stop_reason:
            combo_tests_done = 0
            for first, second in parameter_pairs:
                if combo_tests_done >= MAX_COMBINATION_TESTS:
                    break
                if total_requests >= safe_request_cap:
                    stop_reason = "request_cap_reached"
                    break
                if total_errors >= MAX_ERRORS_BEFORE_STOP:
                    stop_reason = "too_many_request_errors"
                    break

                first_base = first["example_values"][0] if first.get("example_values") else "1"
                second_base = second["example_values"][0] if second.get("example_values") else "1"
                baseline_assignments = [(first, first_base), (second, second_base)]
                method, url, params, data = _build_request_for_assignments(baseline_assignments)
                baseline_response = await _send_request(client, limiter, method, url, params, data)
                total_requests += 1
                combo_tests_done += 1
                if baseline_response.get("error"):
                    total_errors += 1

                baseline_profile = _profile_response(baseline_response)
                baseline_profiles.append(
                    {
                        "target_url": url,
                        "parameter": _format_parameter_label(baseline_assignments),
                        "profile": baseline_profile,
                    }
                )

                for category, payload in combo_payload_plan:
                    if total_requests >= safe_request_cap:
                        stop_reason = "request_cap_reached"
                        break
                    if total_errors >= MAX_ERRORS_BEFORE_STOP:
                        stop_reason = "too_many_request_errors"
                        break

                    assignments = [(first, payload), (second, payload)]
                    method, url, params, data = _build_request_for_assignments(assignments)
                    mutated_response = await _send_request(client, limiter, method, url, params, data)
                    total_requests += 1
                    if mutated_response.get("error"):
                        total_errors += 1

                    mutated_profile = _profile_response(mutated_response)
                    signals = _compute_signals(
                        payload,
                        baseline_response,
                        baseline_profile,
                        mutated_response,
                        mutated_profile,
                    )
                    if not _should_emit_finding(signals):
                        continue
                    finding_candidates.append(
                        {
                            "url": url,
                            "parameter_label": _format_parameter_label(assignments),
                            "payload": payload,
                            "category": category,
                            "parameters": [first, second],
                            "baseline_response": baseline_response,
                            "signals": signals,
                            "mutated_response": mutated_response,
                            "baseline_profile": baseline_profile,
                            "mutated_profile": mutated_profile,
                        }
                    )

                if stop_reason:
                    break

        if anomaly_model is None and baseline_profiles:
            fallback_model, fallback_stats = _train_anomaly_model(baseline_profiles)
            if fallback_model is not None:
                anomaly_model = fallback_model
                anomaly_stats = fallback_stats

        for candidate in finding_candidates:
            baseline_response = dict(candidate.get("baseline_response") or {})
            baseline_profile = dict(candidate.get("baseline_profile") or {})
            mutated_response = dict(candidate.get("mutated_response") or {})
            mutated_profile = dict(candidate.get("mutated_profile") or {})
            signals = dict(candidate.get("signals") or {})
            candidate_params = [
                param for param in (candidate.get("parameters") or []) if isinstance(param, dict)
            ]
            parameter_names = sorted(
                {
                    str(param.get("name") or "").strip()
                    for param in candidate_params
                    if str(param.get("name") or "").strip()
                }
            )

            feature_row = _build_fuzz_feature_row(
                baseline_profile=baseline_profile,
                mutated_profile=mutated_profile,
                signals=signals,
            )
            anomaly_score = _ml_anomaly_score(anomaly_model, feature_row)
            finding = _build_finding(
                url=str(candidate.get("url") or ""),
                parameter_label=str(candidate.get("parameter_label") or ""),
                payload=str(candidate.get("payload") or ""),
                category=str(candidate.get("category") or "generic_anomaly"),
                signals=signals,
                mutated=mutated_response,
                ml_anomaly_score=anomaly_score,
            )

            downstream_scan = await _scan_downstream_for_payload_marker(
                client=client,
                limiter=limiter,
                flow_graph=flow_graph,
                source_url=str(candidate.get("url") or ""),
                parameter_names=parameter_names,
                payload_marker=str(candidate.get("payload") or ""),
                safe_request_cap=safe_request_cap,
                total_requests=total_requests,
                total_errors=total_errors,
            )
            total_requests += int(downstream_scan.get("requests_used") or 0)
            total_errors += int(downstream_scan.get("errors_used") or 0)
            flow_chains = list(downstream_scan.get("flow_chains") or [])
            downstream_hits = list(downstream_scan.get("detections") or [])
            if downstream_hits:
                stored_vulnerability_candidates += 1
                finding["stored_vulnerability_candidate"] = True
                finding["flow_chain_evidence"] = flow_chains
                boosted = min(
                    1.0,
                    max(
                        float(finding.get("confidence_score") or 0.0),
                        float(finding.get("confidence_score") or 0.0) + 0.30,
                    ),
                )
                finding["confidence_score"] = round(boosted, 4)
                finding["severity"] = _severity_from_confidence(boosted)

                for chain in flow_chains:
                    flow_chains_detected.append(dict(chain))
                for hit in downstream_hits:
                    cross_page_reflections.append(
                        {
                            "payload_marker": str(candidate.get("payload") or ""),
                            "source": str(hit.get("source") or ""),
                            "sink": str(hit.get("sink") or ""),
                            "parameter_names": parameter_names,
                            "response_status": int(hit.get("response_status") or 0),
                            "response_time_ms": float(hit.get("response_time_ms") or 0.0),
                            "flow_chain": flow_graph.shortest_path(
                                str(hit.get("source") or ""),
                                str(hit.get("sink") or ""),
                            ),
                        }
                    )

            ai_threshold = AI_REASONING_ANOMALY_THRESHOLD
            should_reason = should_invoke_ai_reasoning(anomaly_score, ai_threshold)
            if should_reason and total_requests < safe_request_cap and total_errors < MAX_ERRORS_BEFORE_STOP:
                ai_reasoning_attempted += 1
                ai_result = await reason_on_anomaly(
                    baseline_response=baseline_response,
                    fuzz_response=mutated_response,
                    detection_signals=finding.get("detection_signals", {}),
                    anomaly_score=anomaly_score,
                    original_payload=str(candidate.get("payload") or ""),
                    parameter=str(candidate.get("parameter_label") or ""),
                    category=str(candidate.get("category") or "generic_anomaly"),
                )

                if ai_result and ai_result.get("refined_payload"):
                    refined_payload = str(ai_result.get("refined_payload") or "").strip()
                    exploitation_likelihood = float(ai_result.get("exploitation_likelihood") or 0.0)
                    escalate_categories = [
                        str(item or "").strip().lower()
                        for item in (ai_result.get("escalate_categories") or [])
                        if str(item or "").strip()
                    ]
                    assignments: List[Tuple[Dict[str, Any], str]] = []
                    for param in candidate_params:
                        if isinstance(param, dict):
                            assignments.append((param, refined_payload))

                    if assignments and total_requests < safe_request_cap:
                        method, url, params, data = _build_request_for_assignments(assignments)
                        refined_response = await _send_request(
                            client, limiter, method, url, params, data
                        )
                        total_requests += 1
                        if refined_response.get("error"):
                            total_errors += 1

                        refined_profile = _profile_response(refined_response)
                        refined_signals = _compute_signals(
                            refined_payload,
                            baseline_response,
                            baseline_profile,
                            refined_response,
                            refined_profile,
                        )
                        refined_feature = _build_fuzz_feature_row(
                            baseline_profile=baseline_profile,
                            mutated_profile=refined_profile,
                            signals=refined_signals,
                        )
                        refined_anomaly = _ml_anomaly_score(anomaly_model, refined_feature)
                        refined_rule_confidence = _confidence_score(refined_signals)
                        refined_combined = _combine_confidence(
                            refined_rule_confidence, refined_anomaly
                        )
                        anomaly_amplified = refined_anomaly > (anomaly_score + 0.02)

                        final_confidence = max(
                            float(finding.get("confidence_score") or 0.0), refined_combined
                        )
                        if anomaly_amplified:
                            amplification_boost = min(
                                0.15, max(0.05, refined_anomaly - anomaly_score)
                            )
                            final_confidence = min(
                                1.0, max(final_confidence, refined_combined + amplification_boost)
                            )

                        finding["confidence_score"] = round(final_confidence, 4)
                        finding["severity"] = _severity_from_confidence(final_confidence)
                        finding["rule_confidence_score"] = round(
                            max(
                                float(finding.get("rule_confidence_score") or 0.0),
                                refined_rule_confidence,
                            ),
                            4,
                        )
                        finding["ml_anomaly_score"] = round(
                            max(float(finding.get("ml_anomaly_score") or 0.0), refined_anomaly), 4
                        )
                        likely_vuln = str(ai_result.get("likely_vulnerability") or "").strip()
                        if likely_vuln and likely_vuln.lower() != "inconclusive":
                            finding["vulnerability_type"] = likely_vuln
                        finding["ai_reasoning"] = {
                            "threshold": ai_threshold,
                            "triggered": True,
                            "rationale": str(ai_result.get("rationale") or ""),
                            "refined_payload": refined_payload,
                            "anomaly_score_initial": anomaly_score,
                            "anomaly_score_refined": refined_anomaly,
                            "anomaly_amplified": anomaly_amplified,
                            "refined_response_status": int(refined_response.get("status_code", 0)),
                            "refined_response_time_ms": float(
                                refined_response.get("response_time_ms", 0.0)
                            ),
                            "refined_rule_confidence": refined_rule_confidence,
                            "refined_combined_confidence": refined_combined,
                            "exploitation_likelihood": exploitation_likelihood,
                            "escalate_categories": escalate_categories,
                            "escalation_tests": [],
                        }
                        ai_reasoning_applied += 1

                        if (
                            exploitation_likelihood >= 0.65
                            and escalate_categories
                            and total_requests < safe_request_cap
                            and total_errors < MAX_ERRORS_BEFORE_STOP
                        ):
                            executed_tests = 0
                            used_payloads = {str(candidate.get("payload") or ""), refined_payload}
                            escalation_records: List[Dict[str, Any]] = []

                            for escalate_category in escalate_categories:
                                if executed_tests >= MAX_ESCALATION_TESTS:
                                    break
                                extra_payloads = _payloads_for_category(
                                    escalate_category,
                                    exclude_payloads=used_payloads,
                                )
                                for escalation_payload in extra_payloads:
                                    if executed_tests >= MAX_ESCALATION_TESTS:
                                        break
                                    if total_requests >= safe_request_cap:
                                        break
                                    if total_errors >= MAX_ERRORS_BEFORE_STOP:
                                        break

                                    escalation_assignments: List[Tuple[Dict[str, Any], str]] = []
                                    for param in candidate_params:
                                        if isinstance(param, dict):
                                            escalation_assignments.append(
                                                (param, escalation_payload)
                                            )
                                    if not escalation_assignments:
                                        continue

                                    method, url, params, data = _build_request_for_assignments(
                                        escalation_assignments
                                    )
                                    escalation_response = await _send_request(
                                        client, limiter, method, url, params, data
                                    )
                                    total_requests += 1
                                    if escalation_response.get("error"):
                                        total_errors += 1

                                    escalation_profile = _profile_response(escalation_response)
                                    escalation_signals = _compute_signals(
                                        escalation_payload,
                                        baseline_response,
                                        baseline_profile,
                                        escalation_response,
                                        escalation_profile,
                                    )
                                    escalation_feature = _build_fuzz_feature_row(
                                        baseline_profile=baseline_profile,
                                        mutated_profile=escalation_profile,
                                        signals=escalation_signals,
                                    )
                                    escalation_anomaly = _ml_anomaly_score(
                                        anomaly_model, escalation_feature
                                    )
                                    escalation_rule = _confidence_score(escalation_signals)
                                    escalation_combined = _combine_confidence(
                                        escalation_rule, escalation_anomaly
                                    )
                                    amplified = escalation_anomaly > (anomaly_score + 0.02)
                                    if amplified:
                                        final_confidence = min(
                                            1.0, max(final_confidence, escalation_combined + 0.05)
                                        )
                                        finding["confidence_score"] = round(final_confidence, 4)
                                        finding["severity"] = _severity_from_confidence(final_confidence)
                                        finding["rule_confidence_score"] = round(
                                            max(
                                                float(finding.get("rule_confidence_score") or 0.0),
                                                escalation_rule,
                                            ),
                                            4,
                                        )
                                        finding["ml_anomaly_score"] = round(
                                            max(
                                                float(finding.get("ml_anomaly_score") or 0.0),
                                                escalation_anomaly,
                                            ),
                                            4,
                                        )

                                    escalation_records.append(
                                        {
                                            "category": escalate_category,
                                            "payload": escalation_payload,
                                            "response_status": int(
                                                escalation_response.get("status_code", 0)
                                            ),
                                            "response_time_ms": float(
                                                escalation_response.get("response_time_ms", 0.0)
                                            ),
                                            "anomaly_score": escalation_anomaly,
                                            "combined_confidence": escalation_combined,
                                            "amplified": amplified,
                                        }
                                    )
                                    executed_tests += 1
                                    used_payloads.add(escalation_payload)

                            finding["ai_reasoning"]["escalation_tests"] = escalation_records

            findings.append(finding)

    return {
        "target_url": target_url,
        "mode": "advanced_aggressive_detection_safe",
        "safe_request_cap": safe_request_cap,
        "payloads_per_parameter": MAX_PAYLOADS_PER_PARAMETER,
        "rate_limit_rps": MAX_REQUESTS_PER_SECOND,
        "timeout_seconds": 5,
        "total_parameters_received": len(parameters),
        "combination_pairs_planned": len(parameter_pairs),
        "total_requests_sent": total_requests,
        "total_request_errors": total_errors,
        "stopped_early": bool(stop_reason),
        "stop_reason": stop_reason,
        "anomaly_model_enabled": anomaly_model_enabled,
        "anomaly_model_trained": anomaly_model is not None,
        "baseline_clustering": anomaly_cluster_info,
        "clean_baseline_responses": len(clean_baseline_profiles),
        "anomaly_training_baselines": len(baseline_profiles),
        "anomaly_feature_centers": anomaly_stats,
        "ai_reasoning_threshold": AI_REASONING_ANOMALY_THRESHOLD,
        "ai_reasoning_attempted": ai_reasoning_attempted,
        "ai_reasoning_applied": ai_reasoning_applied,
        "flow_chains_detected": len(flow_chains_detected),
        "stored_vulnerability_candidates": stored_vulnerability_candidates,
        "longest_parameter_chain": longest_parameter_chain,
        "cross_page_reflections": cross_page_reflections,
        "baseline_profiles": baseline_profiles,
        "findings": findings,
    }
