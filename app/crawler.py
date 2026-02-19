import asyncio
import re
import time
from collections import deque
from html.parser import HTMLParser
from typing import Any, Deque, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx

from app.flow_graph import FlowGraph

MAX_CRAWL_DEPTH = 2
MAX_CRAWL_PAGES = 30
MAX_REQUESTS_PER_SECOND = 5
MIN_REQUEST_INTERVAL = 1.0 / MAX_REQUESTS_PER_SECOND
CRAWLER_USER_AGENT = "ai-secure-crawler/1.0"
SUPPORTED_SCHEMES = {"http", "https"}
FIELD_TAGS = {"input", "textarea", "select"}
JS_STATIC_ASSET_SUFFIXES = (
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".map",
)


def validate_target_url(url: str) -> bool:
    """Validate a target URL for crawling."""
    try:
        parsed = urlparse((url or "").strip())
    except Exception:
        return False

    return bool(parsed.scheme in SUPPORTED_SCHEMES and parsed.netloc)


def _host_key(url: str) -> str:
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return hostname


def _normalize_url(url: str) -> str:
    """Normalize URL so we can deduplicate and avoid crawl loops."""
    try:
        parsed = urlparse(url)
    except Exception:
        return ""

    if parsed.scheme not in SUPPORTED_SCHEMES or not parsed.netloc:
        return ""

    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()
    if hostname.startswith("www."):
        hostname = hostname[4:]

    # Strip default ports to avoid duplicate crawl targets.
    port = parsed.port
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{hostname}:{port}"
    else:
        netloc = hostname

    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")

    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    normalized_query = urlencode(sorted(query_pairs), doseq=True) if query_pairs else ""

    return urlunparse(
        (
            scheme,
            netloc,
            path,
            "",
            normalized_query,
            "",
        )
    )


def _is_internal_url(candidate_url: str, root_host: str) -> bool:
    return _host_key(candidate_url) == root_host


def _extract_query_params(url: str) -> List[str]:
    try:
        return sorted(parse_qs(urlparse(url).query, keep_blank_values=True).keys())
    except Exception:
        return []


def _extract_query_param_values(url: str) -> Dict[str, List[str]]:
    try:
        query_items = parse_qs(urlparse(url).query, keep_blank_values=True)
    except Exception:
        return {}

    extracted: Dict[str, List[str]] = {}
    for name, values in query_items.items():
        clean_name = (name or "").strip()
        if not clean_name:
            continue
        extracted[clean_name] = [value if value is not None else "" for value in values]
    return extracted


def _accumulate_query_params(storage: Dict[str, Set[str]], url: str) -> None:
    for name, values in _extract_query_param_values(url).items():
        if name not in storage:
            storage[name] = set()
        if values:
            storage[name].update(values)
        else:
            storage[name].add("")


def _query_param_details(storage: Dict[str, Set[str]]) -> List[Dict[str, Any]]:
    details: List[Dict[str, Any]] = []
    for name in sorted(storage.keys()):
        details.append(
            {
                "name": name,
                "example_values": sorted(storage.get(name, set())),
            }
        )
    return details


def _unique(values: List[str]) -> List[str]:
    seen: Set[str] = set()
    output: List[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            output.append(value)
    return output


class _PageParser(HTMLParser):
    """Extract links, forms, input fields, and JS references from HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: List[str] = []
        self.script_sources: List[str] = []
        self.forms: List[Dict[str, Any]] = []
        self.input_fields: List[Dict[str, Any]] = []
        self._form_stack: List[Dict[str, Any]] = []

    @staticmethod
    def _attrs_to_dict(attrs: List[Tuple[str, Optional[str]]]) -> Dict[str, str]:
        attr_map: Dict[str, str] = {}
        for key, value in attrs:
            if key:
                attr_map[key.lower()] = "" if value is None else value
        return attr_map

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        tag = tag.lower()
        attr_map = self._attrs_to_dict(attrs)

        if tag == "a":
            href = (attr_map.get("href") or "").strip()
            if href:
                self.links.append(href)
            return

        if tag == "script":
            src = (attr_map.get("src") or "").strip()
            if src:
                self.script_sources.append(src)
            return

        if tag == "form":
            form = {
                "action": (attr_map.get("action") or "").strip(),
                "method": (attr_map.get("method") or "get").lower(),
                "inputs": [],
            }
            self.forms.append(form)
            self._form_stack.append(form)
            return

        if tag in FIELD_TAGS:
            field = {
                "tag": tag,
                "name": (attr_map.get("name") or "").strip(),
                "id": (attr_map.get("id") or "").strip(),
                "type": (attr_map.get("type") or ("text" if tag == "input" else tag)).lower(),
                "required": "required" in attr_map,
                "placeholder": (attr_map.get("placeholder") or "").strip(),
                "value": (attr_map.get("value") or "").strip(),
                "in_form": bool(self._form_stack),
            }
            self.input_fields.append(field)
            if self._form_stack:
                self._form_stack[-1]["inputs"].append(dict(field))

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._form_stack:
            self._form_stack.pop()


def _extract_page_data(page_url: str, html: str, root_host: str) -> Dict[str, Any]:
    parser = _PageParser()
    parser.feed(html or "")
    parser.close()

    query_param_storage: Dict[str, Set[str]] = {}
    _accumulate_query_params(query_param_storage, page_url)
    query_param_sources: Dict[Tuple[str, str], Set[str]] = {}
    internal_links: List[str] = []
    javascript_files: List[str] = []
    normalized_forms: List[Dict[str, Any]] = []

    def collect_query_source(source_url: str) -> None:
        params = _extract_query_param_values(source_url)
        for param_name, values in params.items():
            key = (param_name, source_url)
            if key not in query_param_sources:
                query_param_sources[key] = set()
            query_param_sources[key].update(values)
        _accumulate_query_params(query_param_storage, source_url)

    def normalize_input_field(field: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "tag": str(field.get("tag") or "").lower(),
            "name": str(field.get("name") or "").strip(),
            "id": str(field.get("id") or "").strip(),
            "type": str(field.get("type") or "text").lower(),
            "required": bool(field.get("required")),
            "placeholder": str(field.get("placeholder") or "").strip(),
            "value": str(field.get("value") or "").strip(),
            "in_form": bool(field.get("in_form")),
        }

    def dedupe_input_fields(fields: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen_inputs: Set[Tuple[str, str, str, str, bool, str, str, bool]] = set()
        deduped: List[Dict[str, Any]] = []
        for raw_field in fields:
            field = normalize_input_field(raw_field)
            signature = (
                field["tag"],
                field["name"],
                field["id"],
                field["type"],
                field["required"],
                field["placeholder"],
                field["value"],
                field["in_form"],
            )
            if signature in seen_inputs:
                continue
            seen_inputs.add(signature)
            deduped.append(field)
        return deduped

    for link in parser.links:
        if link.startswith("#"):
            continue
        if link.lower().startswith(("javascript:", "mailto:", "tel:")):
            continue
        absolute_link = _normalize_url(urljoin(page_url, link))
        if not absolute_link:
            continue
        if _is_internal_url(absolute_link, root_host):
            internal_links.append(absolute_link)
            collect_query_source(absolute_link)

    for script_src in parser.script_sources:
        absolute_src = _normalize_url(urljoin(page_url, script_src))
        if not absolute_src:
            continue
        javascript_files.append(absolute_src)
        collect_query_source(absolute_src)

    seen_forms: Set[
        Tuple[str, str, Tuple[Tuple[str, str, str, str, bool], ...]]
    ] = set()
    for form in parser.forms:
        action = (form.get("action") or "").strip()
        resolved_action = _normalize_url(urljoin(page_url, action)) if action else page_url
        method = str(form.get("method", "get") or "get").strip().lower()
        normalized_inputs = dedupe_input_fields(form.get("inputs", []))
        form_signature = (
            resolved_action,
            method,
            tuple(
                (
                    field["name"],
                    field["id"],
                    field["tag"],
                    field["type"],
                    field["required"],
                )
                for field in normalized_inputs
            ),
        )
        if form_signature in seen_forms:
            continue

        seen_forms.add(form_signature)
        collect_query_source(resolved_action)
        normalized_forms.append(
            {"action": resolved_action, "method": method, "inputs": normalized_inputs}
        )

    input_fields = dedupe_input_fields(parser.input_fields)
    query_details = _query_param_details(query_param_storage)
    query_names = [item["name"] for item in query_details]

    fuzz_candidates: List[Dict[str, Any]] = []
    for (param_name, source_url), values in sorted(query_param_sources.items()):
        fuzz_candidates.append(
            {
                "name": param_name,
                "location": "query",
                "method": "GET",
                "target_url": source_url,
                "source_url": source_url,
                "required": False,
                "input_type": "query",
                "example_values": sorted(values),
            }
        )

    for form in normalized_forms:
        method = str(form.get("method", "get")).upper()
        action = str(form.get("action") or page_url)
        for input_field in form.get("inputs", []):
            input_name = str(input_field.get("name") or "").strip()
            if not input_name:
                continue
            candidate_values: List[str] = []
            input_value = str(input_field.get("value") or "")
            if input_value:
                candidate_values.append(input_value)
            fuzz_candidates.append(
                {
                    "name": input_name,
                    "location": "form",
                    "method": method,
                    "target_url": action,
                    "source_url": page_url,
                    "required": bool(input_field.get("required")),
                    "input_type": str(input_field.get("type") or "text"),
                    "example_values": candidate_values,
                }
            )

    deduped_fuzz_params: Dict[
        Tuple[str, str, str, str, str, bool, str], Dict[str, Any]
    ] = {}
    for candidate in fuzz_candidates:
        signature = (
            str(candidate.get("name") or ""),
            str(candidate.get("location") or ""),
            str(candidate.get("method") or ""),
            str(candidate.get("target_url") or ""),
            str(candidate.get("source_url") or ""),
            bool(candidate.get("required")),
            str(candidate.get("input_type") or ""),
        )
        existing = deduped_fuzz_params.get(signature)
        if existing is None:
            normalized_values = [str(v) for v in candidate.get("example_values", [])]
            candidate["example_values"] = _unique(normalized_values)
            deduped_fuzz_params[signature] = candidate
            continue
        merged_values = set(existing.get("example_values", []))
        merged_values.update(str(v) for v in candidate.get("example_values", []))
        existing["example_values"] = sorted(merged_values)

    fuzz_parameters = sorted(
        deduped_fuzz_params.values(),
        key=lambda item: (
            str(item.get("location") or ""),
            str(item.get("name") or ""),
            str(item.get("target_url") or ""),
            str(item.get("method") or ""),
        ),
    )

    return {
        "forms": normalized_forms,
        "input_fields": input_fields,
        "query_parameters": query_names,
        "query_parameters_detailed": query_details,
        "javascript_files": _unique(javascript_files),
        "internal_links": _unique(internal_links),
        "fuzz_parameters": fuzz_parameters,
    }


def analyze_js_content(content: str, source_url: str) -> Dict[str, Any]:
    """Analyze JavaScript content for risky patterns and API endpoints."""
    text = str(content or "")
    findings: List[Dict[str, str]] = []
    discovered_endpoints: List[str] = []
    seen_findings: Set[Tuple[str, str, str]] = set()

    def add_finding(
        finding_type: str, severity: str, message: str, evidence: str
    ) -> None:
        compact = re.sub(r"\s+", " ", str(evidence or "")).strip()
        if len(compact) > 200:
            compact = f"{compact[:197]}..."
        signature = (finding_type, message, compact)
        if signature in seen_findings:
            return
        seen_findings.add(signature)
        findings.append(
            {
                "source_url": source_url,
                "type": finding_type,
                "severity": severity,
                "message": message,
                "evidence": compact,
            }
        )

    def iter_limited(pattern: re.Pattern[str], max_hits: int = 20):
        count = 0
        for match in pattern.finditer(text):
            yield match
            count += 1
            if count >= max_hits:
                break

    detection_patterns: List[Tuple[str, str, str, re.Pattern[str]]] = [
        (
            "innerhtml_assignment",
            "Medium",
            "innerHTML assignment can enable DOM XSS if input is unsanitized.",
            re.compile(r"\.\s*innerHTML\s*=", re.IGNORECASE),
        ),
        (
            "document_write",
            "Medium",
            "document.write usage can introduce script injection risks.",
            re.compile(r"\bdocument\.write\s*\(", re.IGNORECASE),
        ),
        (
            "eval_usage",
            "High",
            "eval usage detected.",
            re.compile(r"\beval\s*\(", re.IGNORECASE),
        ),
        (
            "settimeout_string",
            "Medium",
            "setTimeout called with a string argument.",
            re.compile(
                r"\bsetTimeout\s*\(\s*(['\"`])(?:(?!\1).){1,400}\1\s*(?:,|\))",
                re.IGNORECASE | re.DOTALL,
            ),
        ),
        (
            "fetch_concat_input",
            "Medium",
            "fetch call appears to concatenate dynamic input into URL/body.",
            re.compile(
                r"\bfetch\s*\(\s*[^)]{0,500}(?:\+|\$\{)[^)]{0,500}\)",
                re.IGNORECASE | re.DOTALL,
            ),
        ),
        (
            "xhr_concat_input",
            "Medium",
            "XMLHttpRequest.open appears to concatenate dynamic input into URL.",
            re.compile(
                r"\.open\s*\(\s*['\"](?:GET|POST|PUT|PATCH|DELETE|OPTIONS)['\"]\s*,\s*[^,\)]{0,500}(?:\+|\$\{)",
                re.IGNORECASE | re.DOTALL,
            ),
        ),
        (
            "hardcoded_secret",
            "High",
            "Potential hardcoded API key/token/secret found in JavaScript.",
            re.compile(
                r"(?:api[_\-]?key|token|secret|access[_\-]?token)\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{12,}['\"]",
                re.IGNORECASE,
            ),
        ),
    ]

    for finding_type, severity, message, pattern in detection_patterns:
        for match in iter_limited(pattern):
            add_finding(finding_type, severity, message, match.group(0))

    endpoint_literal_pattern = re.compile(
        r"""(?P<quote>['"`])(?P<endpoint>(?:https?://|//|/)[^'"`\s]{1,280})(?P=quote)""",
        re.IGNORECASE,
    )
    xhr_url_pattern = re.compile(
        r"""\.open\s*\(\s*['"](?:GET|POST|PUT|PATCH|DELETE|OPTIONS)['"]\s*,\s*(?P<quote>['"`])(?P<endpoint>[^'"`]{1,280})(?P=quote)""",
        re.IGNORECASE,
    )
    fetch_url_pattern = re.compile(
        r"""\bfetch\s*\(\s*(?P<quote>['"`])(?P<endpoint>[^'"`]{1,280})(?P=quote)""",
        re.IGNORECASE,
    )

    def normalize_endpoint(raw_endpoint: str) -> str:
        endpoint = str(raw_endpoint or "").strip()
        if not endpoint:
            return ""
        endpoint = endpoint.rstrip(".,);")
        endpoint = re.sub(r"\$\{[^}]+\}", "1", endpoint)
        endpoint = re.sub(r"\{[^}]+\}", "1", endpoint)
        if endpoint.lower().startswith(("javascript:", "data:", "mailto:", "tel:")):
            return ""
        if endpoint.startswith("//"):
            parsed_source = urlparse(source_url)
            endpoint = f"{parsed_source.scheme or 'https'}:{endpoint}"
        lowered = endpoint.lower()
        if lowered.endswith(JS_STATIC_ASSET_SUFFIXES):
            return ""
        normalized = _normalize_url(urljoin(source_url, endpoint))
        return normalized

    for pattern in (endpoint_literal_pattern, xhr_url_pattern, fetch_url_pattern):
        for match in iter_limited(pattern, max_hits=50):
            endpoint = normalize_endpoint(match.group("endpoint"))
            if endpoint:
                discovered_endpoints.append(endpoint)

    return {
        "source_url": source_url,
        "findings": findings,
        "potential_api_endpoints": _unique(discovered_endpoints),
    }


async def crawl_site(target_url: str, max_depth: int = MAX_CRAWL_DEPTH) -> Dict[str, Any]:
    """Crawl a target URL (internal links only) and extract structured metadata."""
    if not validate_target_url(target_url):
        raise ValueError("Invalid URL. Provide an absolute HTTP/HTTPS URL.")

    start_url = _normalize_url(target_url.strip())
    if not start_url:
        raise ValueError("Invalid URL. Provide an absolute HTTP/HTTPS URL.")

    crawl_depth = max(0, min(max_depth, MAX_CRAWL_DEPTH))
    root_host = _host_key(start_url)
    if not root_host:
        raise ValueError("Invalid URL host.")

    pages: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    crawled_urls: Set[str] = set()
    discovered_urls: Set[str] = {start_url}
    queue: Deque[Tuple[str, int]] = deque([(start_url, 0)])
    requests_sent = 0
    last_request_time = 0.0
    flow_graph = FlowGraph()
    js_analysis_cache: Dict[str, Dict[str, Any]] = {}

    timeout = httpx.Timeout(20.0, connect=10.0)
    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": CRAWLER_USER_AGENT},
    ) as client:
        async def fetch_with_limits(url: str) -> Tuple[Optional[httpx.Response], Optional[str]]:
            nonlocal requests_sent, last_request_time
            if requests_sent >= MAX_CRAWL_PAGES:
                return None, "Request cap reached"

            elapsed = time.monotonic() - last_request_time
            if last_request_time > 0.0 and elapsed < MIN_REQUEST_INTERVAL:
                await asyncio.sleep(MIN_REQUEST_INTERVAL - elapsed)

            try:
                response = await client.get(url)
                requests_sent += 1
                last_request_time = time.monotonic()
                return response, None
            except httpx.HTTPError as exc:
                requests_sent += 1
                last_request_time = time.monotonic()
                return None, f"Request failed: {exc}"

        while queue and requests_sent < MAX_CRAWL_PAGES:
            current_url, depth = queue.popleft()
            current_url = _normalize_url(current_url)
            if not current_url:
                continue

            if current_url in crawled_urls:
                continue

            response, request_error = await fetch_with_limits(current_url)
            if response is None:
                if request_error == "Request cap reached":
                    break
                crawled_urls.add(current_url)
                errors.append(
                    {"url": current_url, "depth": depth, "error": request_error or "Request failed"}
                )
                continue

            final_url = _normalize_url(str(response.url)) or current_url
            if not _is_internal_url(final_url, root_host):
                crawled_urls.add(current_url)
                errors.append(
                    {
                        "url": current_url,
                        "depth": depth,
                        "error": "Redirected to external domain",
                    }
                )
                continue

            if final_url in crawled_urls:
                continue

            crawled_urls.add(final_url)
            discovered_urls.add(final_url)

            if response.status_code >= 400:
                errors.append(
                    {
                        "url": final_url,
                        "depth": depth,
                        "error": f"HTTP {response.status_code}",
                    }
                )
                continue

            content_type = (response.headers.get("content-type") or "").lower()
            response_type = content_type.split(";")[0].strip() if content_type else "unknown"
            if "text/html" not in content_type:
                param_values = _extract_query_param_values(final_url)
                query_names = sorted(param_values.keys())
                query_details = [
                    {"name": name, "example_values": sorted(values)}
                    for name, values in sorted(param_values.items())
                ]
                fuzz_parameters = [
                    {
                        "name": name,
                        "location": "query",
                        "method": "GET",
                        "target_url": final_url,
                        "source_url": final_url,
                        "required": False,
                        "input_type": "query",
                        "example_values": sorted(values),
                    }
                    for name, values in sorted(param_values.items())
                ]
                pages.append(
                    {
                        "url": final_url,
                        "depth": depth,
                        "response_type": response_type or "other",
                        "status_code": response.status_code,
                        "forms": [],
                        "input_fields": [],
                        "query_parameters": query_names,
                        "query_parameters_detailed": query_details,
                        "javascript_files": [],
                        "js_findings": [],
                        "discovered_endpoints": [],
                        "internal_links": [],
                        "fuzz_parameters": fuzz_parameters,
                    }
                )
                flow_graph.add_node(
                    final_url,
                    {
                        "depth": depth,
                        "response_type": response_type or "other",
                        "parameters": query_names,
                    },
                )
                continue

            extracted = _extract_page_data(final_url, response.text, root_host)
            page_js_findings: List[Dict[str, str]] = []
            page_discovered_endpoints: List[str] = []

            for script_url in extracted["javascript_files"]:
                normalized_script_url = _normalize_url(script_url)
                if not normalized_script_url:
                    continue

                cached_analysis = js_analysis_cache.get(normalized_script_url)
                if cached_analysis is None:
                    js_response, js_error = await fetch_with_limits(normalized_script_url)
                    if js_response is None:
                        if js_error and js_error != "Request cap reached":
                            errors.append(
                                {
                                    "url": normalized_script_url,
                                    "depth": depth,
                                    "error": f"JS fetch failed: {js_error}",
                                }
                            )
                        cached_analysis = {
                            "source_url": normalized_script_url,
                            "findings": [],
                            "potential_api_endpoints": [],
                        }
                    elif js_response.status_code >= 400:
                        errors.append(
                            {
                                "url": normalized_script_url,
                                "depth": depth,
                                "error": f"JS HTTP {js_response.status_code}",
                            }
                        )
                        cached_analysis = {
                            "source_url": normalized_script_url,
                            "findings": [],
                            "potential_api_endpoints": [],
                        }
                    else:
                        cached_analysis = analyze_js_content(
                            js_response.text, normalized_script_url
                        )
                    js_analysis_cache[normalized_script_url] = cached_analysis

                for finding in cached_analysis.get("findings", []):
                    if isinstance(finding, dict):
                        page_js_findings.append(dict(finding))

                for endpoint in cached_analysis.get("potential_api_endpoints", []):
                    normalized_endpoint = _normalize_url(endpoint)
                    if not normalized_endpoint:
                        continue
                    if not _is_internal_url(normalized_endpoint, root_host):
                        continue
                    page_discovered_endpoints.append(normalized_endpoint)

            deduped_js_findings: List[Dict[str, str]] = []
            seen_js_findings: Set[Tuple[str, str, str]] = set()
            for finding in page_js_findings:
                source = str(finding.get("source_url") or "")
                finding_type = str(finding.get("type") or "")
                evidence = str(finding.get("evidence") or "")
                signature = (source, finding_type, evidence)
                if signature in seen_js_findings:
                    continue
                seen_js_findings.add(signature)
                deduped_js_findings.append(finding)

            deduped_endpoints = _unique(page_discovered_endpoints)
            form_parameters: Set[str] = set()
            for form in extracted["forms"]:
                if not isinstance(form, dict):
                    continue
                for input_item in form.get("inputs", []):
                    if not isinstance(input_item, dict):
                        continue
                    input_name = str(input_item.get("name") or "").strip()
                    if input_name:
                        form_parameters.add(input_name)

            node_parameters = sorted(
                set(extracted["query_parameters"]).union(form_parameters)
            )
            page_result = {
                "url": final_url,
                "depth": depth,
                "response_type": response_type or "html",
                "status_code": response.status_code,
                "forms": extracted["forms"],
                "input_fields": extracted["input_fields"],
                "query_parameters": extracted["query_parameters"],
                "query_parameters_detailed": extracted["query_parameters_detailed"],
                "javascript_files": extracted["javascript_files"],
                "js_findings": deduped_js_findings,
                "discovered_endpoints": deduped_endpoints,
                "internal_links": extracted["internal_links"],
                "fuzz_parameters": extracted["fuzz_parameters"],
            }
            pages.append(page_result)
            flow_graph.add_node(
                final_url,
                {
                    "depth": depth,
                    "response_type": response_type or "html",
                    "parameters": node_parameters,
                },
            )

            for link in extracted["internal_links"]:
                destination = _normalize_url(link)
                if not destination:
                    continue
                query_values = _extract_query_param_values(destination)
                if query_values:
                    for param_name, values in sorted(query_values.items()):
                        flow_graph.add_edge(
                            final_url,
                            destination,
                            parameter=param_name,
                            method="GET",
                            example_value=str(values[0] if values else ""),
                        )
                else:
                    flow_graph.add_edge(
                        final_url,
                        destination,
                        parameter="",
                        method="GET",
                        example_value="",
                    )

            for endpoint_url in deduped_endpoints:
                destination = _normalize_url(endpoint_url)
                if not destination:
                    continue
                query_values = _extract_query_param_values(destination)
                if query_values:
                    for param_name, values in sorted(query_values.items()):
                        flow_graph.add_edge(
                            final_url,
                            destination,
                            parameter=param_name,
                            method="GET",
                            example_value=str(values[0] if values else ""),
                        )
                else:
                    flow_graph.add_edge(
                        final_url,
                        destination,
                        parameter="",
                        method="GET",
                        example_value="",
                    )

            for form in extracted["forms"]:
                if not isinstance(form, dict):
                    continue
                action = _normalize_url(str(form.get("action") or "").strip())
                if not action:
                    continue
                method = str(form.get("method") or "GET").upper()
                inputs = form.get("inputs", [])
                if not isinstance(inputs, list) or not inputs:
                    flow_graph.add_edge(
                        final_url,
                        action,
                        parameter="",
                        method=method,
                        example_value="",
                    )
                    continue
                added = False
                for input_item in inputs:
                    if not isinstance(input_item, dict):
                        continue
                    input_name = str(input_item.get("name") or "").strip()
                    input_value = str(input_item.get("value") or "").strip()
                    if not input_name:
                        continue
                    added = True
                    flow_graph.add_edge(
                        final_url,
                        action,
                        parameter=input_name,
                        method=method,
                        example_value=input_value,
                    )
                if not added:
                    flow_graph.add_edge(
                        final_url,
                        action,
                        parameter="",
                        method=method,
                        example_value="",
                    )

            if depth >= crawl_depth:
                continue

            next_depth = depth + 1
            crawl_candidates = _unique(
                extracted["internal_links"] + deduped_endpoints
            )
            for link in crawl_candidates:
                normalized_link = _normalize_url(link)
                if not normalized_link:
                    continue
                if normalized_link in discovered_urls or normalized_link in crawled_urls:
                    continue
                queue.append((normalized_link, next_depth))
                discovered_urls.add(normalized_link)

    unique_query_params = sorted(
        {
            parameter
            for page in pages
            for parameter in page.get("query_parameters", [])
        }
    )
    unique_javascript_files = sorted(
        {script for page in pages for script in page.get("javascript_files", [])}
    )
    all_js_findings: List[Dict[str, str]] = [
        finding
        for page in pages
        for finding in page.get("js_findings", [])
        if isinstance(finding, dict)
    ]
    js_findings_by_type: Dict[str, int] = {}
    for finding in all_js_findings:
        finding_type = str(finding.get("type") or "").strip()
        if not finding_type:
            continue
        js_findings_by_type[finding_type] = js_findings_by_type.get(finding_type, 0) + 1
    unique_discovered_endpoints = sorted(
        {
            endpoint
            for page in pages
            for endpoint in page.get("discovered_endpoints", [])
            if str(endpoint or "").strip()
        }
    )
    all_fuzz_parameters: Dict[
        Tuple[str, str, str, str, str, bool, str], Dict[str, Any]
    ] = {}
    for page in pages:
        for parameter in page.get("fuzz_parameters", []):
            key = (
                str(parameter.get("name") or ""),
                str(parameter.get("location") or ""),
                str(parameter.get("method") or ""),
                str(parameter.get("target_url") or ""),
                str(parameter.get("source_url") or ""),
                bool(parameter.get("required")),
                str(parameter.get("input_type") or ""),
            )
            existing = all_fuzz_parameters.get(key)
            if existing is None:
                parameter_copy = dict(parameter)
                parameter_copy["example_values"] = _unique(
                    [str(v) for v in parameter_copy.get("example_values", [])]
                )
                all_fuzz_parameters[key] = parameter_copy
                continue
            merged_values = set(existing.get("example_values", []))
            merged_values.update(str(v) for v in parameter.get("example_values", []))
            existing["example_values"] = sorted(merged_values)

    return {
        "target_url": start_url,
        "max_depth": crawl_depth,
        "max_pages": MAX_CRAWL_PAGES,
        "rate_limit_rps": MAX_REQUESTS_PER_SECOND,
        "pages_crawled": len(pages),
        "requests_sent": requests_sent,
        "pages": pages,
        "flow_graph": flow_graph.export_graph_json(),
        "fuzz_parameters": sorted(
            all_fuzz_parameters.values(),
            key=lambda item: (
                str(item.get("location") or ""),
                str(item.get("name") or ""),
                str(item.get("target_url") or ""),
                str(item.get("method") or ""),
            ),
        ),
        "summary": {
            "total_forms": sum(len(page.get("forms", [])) for page in pages),
            "total_input_fields": sum(len(page.get("input_fields", [])) for page in pages),
            "unique_query_parameters": unique_query_params,
            "javascript_files": unique_javascript_files,
            "discovered_endpoints": unique_discovered_endpoints,
            "js_vulnerabilities": {
                "total_findings": len(all_js_findings),
                "findings_by_type": dict(sorted(js_findings_by_type.items())),
            },
            "total_fuzz_parameters": len(all_fuzz_parameters),
            "visited_urls": len(crawled_urls),
        },
        "errors": errors,
    }
