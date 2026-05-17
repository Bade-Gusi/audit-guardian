from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import get_settings
from app.api import auth, cases, reports, admin

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    description="反作弊与行为审计系统 - 服务端API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(auth.router, prefix="/api/auth", tags=["认证"])
app.include_router(cases.router, prefix="/api/cases", tags=["案件"])
app.include_router(reports.router, prefix="/api/reports", tags=["报告"])
app.include_router(admin.router, prefix="/api/admin", tags=["管理"])


@app.get("/api/health")
async def health_check():
    return {"status": "ok", "version": "1.0.0"}
