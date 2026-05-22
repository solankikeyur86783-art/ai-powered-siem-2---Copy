from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import MongoClient
from loguru import logger
from app.config import get_settings
from typing import Optional, Any

settings = get_settings()

# Async client for FastAPI
async_client: Optional["AsyncIOMotorClient"] = None
async_db: Optional[Any] = None

# Sync client for background tasks
sync_client: Optional["MongoClient"] = None
sync_db: Optional[Any] = None


async def connect_db():
    global async_client, async_db
    try:
        async_client = AsyncIOMotorClient(settings.mongodb_url, serverSelectionTimeoutMS=5000)
        await async_client.admin.command("ping")
        async_db = async_client[settings.mongodb_db_name]
        logger.success(f"✅ MongoDB connected: {settings.mongodb_url}/{settings.mongodb_db_name}")
    except Exception as e:
        logger.error(f"❌ MongoDB connection failed: {e}")
        raise


async def disconnect_db():
    global async_client
    if async_client:
        async_client.close()
        logger.info("MongoDB disconnected")


def get_sync_db():
    global sync_client, sync_db
    if sync_client is None:
        sync_client = MongoClient(settings.mongodb_url, serverSelectionTimeoutMS=5000)
        sync_db = sync_client[settings.mongodb_db_name]
    return sync_db


def get_db():
    return async_db


# Collection helpers
def col(name: str):
    if async_db is None:
        raise RuntimeError(f"Database not connected. Call connect_db() before accessing collection '{name}'.")
    return async_db[name]
