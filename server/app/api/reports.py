from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db
from app.schemas.report import ReportUpload, ReportListItem, ReviewMarkCreate, ReviewMarkResponse

router = APIRouter()


@router.post("")
async def upload_report(report: ReportUpload, db: AsyncSession = Depends(get_db)):
    """上传加密的审计报告"""
    # TODO: Decrypt, validate, and store report
    return {
        "status": "received",
        "case_name": report.case_name,
        "report_id": "placeholder-uuid",
    }


@router.get("", response_model=list[ReportListItem])
async def list_reports(
    case_id: str | None = None,
    skip: int = 0,
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
):
    """获取报告列表"""
    return []


@router.get("/{report_id}")
async def get_report(report_id: str, db: AsyncSession = Depends(get_db)):
    """获取报告详情"""
    raise HTTPException(status_code=404, detail="报告未找到")


@router.get("/{report_id}/decrypt")
async def get_decrypted_report(report_id: str, db: AsyncSession = Depends(get_db)):
    """获取解密后的报告（需审核员权限）"""
    raise HTTPException(status_code=404, detail="报告未找到")


@router.post("/{report_id}/marks", response_model=ReviewMarkResponse)
async def add_mark(
    report_id: str,
    mark: ReviewMarkCreate,
    db: AsyncSession = Depends(get_db),
):
    """添加审核标记"""
    raise HTTPException(status_code=404, detail="报告未找到")


@router.get("/{report_id}/marks", response_model=list[ReviewMarkResponse])
async def get_marks(report_id: str, db: AsyncSession = Depends(get_db)):
    """获取审核标记列表"""
    return []


@router.get("/{report_id}/compare/{other_report_id}")
async def compare_reports(report_id: str, other_report_id: str):
    """对比两份报告"""
    return {"differences": []}
