import os
from typing import Optional
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv

load_dotenv()

# Read MONGO_URI from environment (matches .env file key)
MONGO_URI: Optional[str] = os.getenv("MONGO_URI")

# Internal globals - initialized lazily to avoid blocking on import
_client: Optional[AsyncIOMotorClient] = None


def _validate_uri() -> None:
    if not MONGO_URI:
        raise RuntimeError("MONGO_URI is not set. Set it in .env or environment variables")


async def get_client() -> AsyncIOMotorClient:
    """Return a lazily-initialized AsyncIOMotorClient.

    The client is created on first use to avoid network activity during import.
    """
    global _client
    if _client is None:
        _validate_uri()
        # short timeouts so requests fail fast in development
        _client = AsyncIOMotorClient(MONGO_URI, serverSelectionTimeoutMS=5000, connectTimeoutMS=5000)
    return _client


async def get_reports_collection():
    """Return the `reports` collection (async). Raises on missing config or connection issues."""
    _validate_uri()
    client = await get_client()
    db = client["securecode_db"]
    return db["reports"]


__all__ = ["MONGO_URI", "get_client", "get_reports_collection"]
