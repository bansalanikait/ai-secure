import re
import tempfile
import shutil
import zipfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse
import httpx
from starlette.concurrency import run_in_threadpool


async def validate_github_url(url: str) -> bool:
    """Validate that the URL is a public GitHub repository."""
    try:
        parsed = urlparse(url)
        # Only allow github.com
        if parsed.netloc not in ('github.com', 'www.github.com'):
            return False
        # Pattern: https://github.com/owner/repo or https://github.com/owner/repo.git
        pattern = r'^https?://(www\.)?github\.com/[\w\-]+/[\w\-\.]+/?$'
        return bool(re.match(pattern, url.rstrip('/')))
    except Exception:
        return False


def _extract_repo_archive(content: bytes) -> str:
    """Write zip bytes and extract archive in a worker thread."""
    temp_dir = tempfile.mkdtemp(prefix="securecode_repo_")
    zip_path = Path(temp_dir) / "repo.zip"
    try:
        with open(zip_path, "wb") as f:
            f.write(content)

        with zipfile.ZipFile(zip_path, "r") as z:
            z.extractall(temp_dir)

        zip_path.unlink(missing_ok=True)

        contents = list(Path(temp_dir).iterdir())
        extracted_dir = next((d for d in contents if d.is_dir()), None)
        return str(extracted_dir) if extracted_dir else temp_dir
    except Exception:
        cleanup_temp_directory(temp_dir)
        raise


async def download_github_repo(repo_url: str) -> Optional[str]:
    """Download a GitHub repo as a zip file and extract it to a temp directory.
    
    Returns the path to the extracted directory or None on failure.
    Caller is responsible for cleanup using shutil.rmtree().
    """
    # Validate URL
    if not await validate_github_url(repo_url):
        raise ValueError("Invalid GitHub URL. Only public github.com repos are supported.")

    # Convert URL to zip download URL
    # https://github.com/owner/repo -> https://github.com/owner/repo/archive/refs/heads/main.zip
    repo_url_clean = repo_url.rstrip("/")
    if repo_url_clean.endswith(".git"):
        repo_url_clean = repo_url_clean[:-4]

    # Try main branch first, then master
    for branch in ["main", "master"]:
        zip_url = f"{repo_url_clean}/archive/refs/heads/{branch}.zip"

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(zip_url, follow_redirects=True)
                if response.status_code == 200:
                    # File write and extraction are blocking; offload to threadpool.
                    return await run_in_threadpool(
                        _extract_repo_archive, response.content
                    )
        except Exception as e:
            print(f"Failed to download from branch {branch}: {e}")
            continue

    raise RuntimeError("Failed to download repository. Ensure it exists and is public.")


def cleanup_temp_directory(temp_dir: str) -> bool:
    """Safely delete a temporary directory."""
    try:
        path = Path(temp_dir)
        if path.exists() and path.is_dir():
            shutil.rmtree(path)
        return True
    except Exception as e:
        print(f"Failed to cleanup {temp_dir}: {e}")
        return False
