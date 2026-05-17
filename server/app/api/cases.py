from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db
from app.schemas.case import CaseListItem, CaseDetail, CaseUpdate

router = APIRouter()


@router.get("", response_model=list[CaseListItem])
async def list_cases(
    skip: int = 0,
    limit: int = 20,
    status: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """获取案件列表"""
    # TODO: Implement with actual DB queries
    return []


@router.get("/{case_id}", response_model=CaseDetail)
async def get_case(case_id: str, db: AsyncSession = Depends(get_db)):
    """获取案件详情"""
    raise HTTPException(status_code=404, detail="案件未找到")


@router.patch("/{case_id}", response_model=CaseDetail)
async def update_case(
    case_id: str,
    update: CaseUpdate,
    db: AsyncSession = Depends(get_db),
):
    """更新案件信息"""
    raise HTTPException(status_code=404, detail="案件未找到")


@router.delete("/{case_id}")
async def delete_case(case_id: str, db: AsyncSession = Depends(get_db)):
    """删除案件"""
    return {"status": "deleted"}
