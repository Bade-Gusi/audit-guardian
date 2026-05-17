from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db

router = APIRouter()


@router.get("/stats")
async def get_stats(db: AsyncSession = Depends(get_db)):
    """系统统计信息"""
    return {
        "total_cases": 0,
        "total_reports": 0,
        "pending_review": 0,
        "active_users": 0,
    }


@router.get("/users")
async def list_users(db: AsyncSession = Depends(get_db)):
    """用户列表"""
    return []


@router.post("/license/generate")
async def generate_license():
    """生成新的License密钥"""
    return {
        "license_key": "placeholder-license-key",
        "hardware_id": None,
        "expires_at": "2027-05-17T00:00:00Z",
    }
