from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db
from app.schemas.auth import LoginRequest, TokenResponse, UserInfo

router = APIRouter()


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest, db: AsyncSession = Depends(get_db)):
    """用户登录，返回JWT token"""
    # TODO: Implement actual authentication
    if request.username == "admin" and request.password == "admin":
        return TokenResponse(
            access_token="placeholder-jwt-token",
            expires_in=1440,
        )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="用户名或密码错误",
    )


@router.post("/refresh")
async def refresh_token():
    """刷新token"""
    return {"access_token": "placeholder", "token_type": "bearer"}


@router.get("/me", response_model=UserInfo)
async def get_current_user():
    """获取当前用户信息"""
    return UserInfo(
        id="1",
        username="admin",
        role="admin",
        display_name="管理员",
    )
