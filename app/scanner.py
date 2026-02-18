import re
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

# Modular rule structure
RULES = [
    {"id": "sql_concat", "name": "SQL Injection Risk", "pattern": r"SELECT.*\+", "severity": "High", "fix": "Use parameterized queries instead of string concatenation."},
    {"id": "debug_true", "name": "Debug Mode Enabled", "pattern": r"debug\s*=\s*True|debug=True", "severity": "Medium", "fix": "Disable debug mode in production."},
    {"id": "hardcoded_password", "name": "Hardcoded Password", "pattern": r"password\s*=\s*['\"].+['\"]", "severity": "High", "fix": "Store secrets in environment variables."},
    {"id": "xss_script", "name": "Reflected XSS (script tag)", "pattern": r"<script[\s>]", "severity": "High", "fix": "Escape or sanitize user input before rendering in HTML."},
    {"id": "eval_usage", "name": "eval() usage", "pattern": r"\beval\s*\(", "severity": "High", "fix": "Avoid eval(); use safer parsing/execution patterns."},
    {"id": "hardcoded_api_key", "name": "Hardcoded API Key", "pattern": r"api_key\s*=\s*['\"][A-Za-z0-9_\-]{8,}['\"]", "severity": "High", "fix": "Keep API keys in environment variables or vault."},
    {"id": "insecure_http", "name": "Insecure HTTP URL", "pattern": r"http://[\w\.-]+", "severity": "Medium", "fix": "Use HTTPS for all external endpoints."},
    {"id": "weak_hash", "name": "Weak Hashing Function", "pattern": r"\b(md5|sha1)\b", "severity": "High", "fix": "Use modern hashing like bcrypt, scrypt, or Argon2."},
    {"id": "dangerous_subprocess", "name": "Dangerous subprocess usage", "pattern": r"subprocess\.(system|Popen)\s*\(", "severity": "High", "fix": "Avoid shell=True and validate arguments; use safe APIs."},
    {"id": "open_cors", "name": "Open CORS Configuration", "pattern": r"allow_origins\s*=\s*\[?\s*\"\*\"", "severity": "Medium", "fix": "Restrict CORS origins to trusted domains."},
    {"id": "insecure_jwt", "name": "Insecure JWT handling", "pattern": r"jwt\.decode\(|jwt\s*\.\s*encode\(|alg\s*[:=]\s*['\"]?none['\"]?", "severity": "High", "fix": "Use strong algorithms and validate tokens properly."},
    {"id": "exposed_secrets", "name": "Exposed Secret Key", "pattern": r"SECRET_KEY\s*=\s*['\"].{8,}['\"]", "severity": "High", "fix": "Rotate and store secrets securely."}
]

SEVERITY_PENALTY = {"High": 30, "Medium": 15, "Low": 5}

# File extensions to scan
SCANNABLE_EXTENSIONS = {'.py', '.js', '.ts', '.jsx', '.tsx', '.json', '.env', '.yml', '.yaml', '.xml', '.html', '.css'}
IGNORE_DIRS = {'node_modules', '.git', 'venv', 'build', 'dist', '__pycache__', '.pytest_cache', '.venv'}


async def scan_code(code: str) -> Dict[str, Any]:
    """Scan code string and return security score, grade, and vulnerabilities."""
    vulnerabilities: List[Dict[str, str]] = []
    score = 100

    for rule in RULES:
        try:
            if re.search(rule["pattern"], code, re.IGNORECASE):
                vulnerabilities.append({
                    "id": rule["id"],
                    "issue": rule["name"],
                    "severity": rule["severity"],
                    "recommended_fix": rule["fix"]
                })
                score -= SEVERITY_PENALTY.get(rule["severity"], 0)
        except re.error:
            continue

    if score < 0:
        score = 0

    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    return {"timestamp": datetime.utcnow(), "score": score, "grade": grade, "vulnerabilities": vulnerabilities}


def scan_file_lines(file_path: str, code: str) -> List[Dict[str, Any]]:
    """Scan a file and return line-level vulnerabilities with code snippets."""
    lines = code.split('\n')
    vulnerabilities = []

    for rule in RULES:
        try:
            for line_idx, line in enumerate(lines, start=1):
                if re.search(rule["pattern"], line, re.IGNORECASE):
                    vulnerabilities.append({
                        "file": file_path,
                        "line": line_idx,
                        "code": line.strip(),
                        "issue": rule["name"],
                        "severity": rule["severity"],
                        "recommended_fix": rule["fix"]
                    })
        except re.error:
            continue

    return vulnerabilities


def scan_directory(repo_path: str) -> Dict[str, Any]:
    """Recursively scan a directory and aggregate all vulnerabilities.
    
    Returns:
        {
            "total_files": int,
            "total_vulnerabilities": int,
            "vulnerabilities": List[vulnerability_with_file_and_line]
        }
    """
    repo_path = Path(repo_path)
    all_vulnerabilities = []
    files_scanned = 0

    for file_path in repo_path.rglob("*"):
        # Skip directories and ignored folders
        if file_path.is_dir():
            continue
        if any(ignored in file_path.parts for ignored in IGNORE_DIRS):
            continue
        # Only scan code files
        if file_path.suffix not in SCANNABLE_EXTENSIONS:
            continue

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            print(f"Failed to read {file_path}: {e}")
            continue

        files_scanned += 1
        relative_path = file_path.relative_to(repo_path)
        vulnerabilities = scan_file_lines(str(relative_path), content)
        all_vulnerabilities.extend(vulnerabilities)

    # Calculate aggregate score
    score = 100
    for vuln in all_vulnerabilities:
        score -= SEVERITY_PENALTY.get(vuln["severity"], 0)
    if score < 0:
        score = 0

    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    return {
        "timestamp": datetime.utcnow(),
        "total_files": files_scanned,
        "total_vulnerabilities": len(all_vulnerabilities),
        "score": score,
        "grade": grade,
        "vulnerabilities": all_vulnerabilities
    }

