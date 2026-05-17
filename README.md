# 赛审卫士 · 反作弊与行为审计系统

## 项目概述

赛审卫士是一个 Windows 桌面软件，用于全面检查目标电脑是否曾运行作弊程序，并完整回溯用户操作痕迹。系统提供优雅的 UI/UX 和强加密保护，支持人工远程审核。

## 核心功能

| 模块 | 功能 |
|------|------|
| 硬件指纹采集 | CPU/GPU/主板/硬盘/网卡/内存信息，硬件变动历史，伪装检测 |
| 全量操作日志 | Windows事件日志、Prefetch、Shellbags、USB记录、文件活动 |
| 反作弊扫描 | 进程/服务/驱动黑名单匹配，SSDT Hook检测，内核回调检测 |
| 报告管理 | 加密报告生成，HTML/PDF导出，上传审核服务器 |
| 远程审核 | 审核员Web面板，案件管理，审核标记，报告对比 |

## 项目结构

```
赛审卫士/
├── client/           # Electron桌面客户端 (React + TypeScript)
├── server/           # FastAPI后端服务 (Python)
├── audit-panel/      # 审核员Web面板 (React + TypeScript)
├── scripts/          # 构建脚本
└── docs/             # 文档
```

## 快速开始

### 前置要求

- Node.js 18+
- .NET 8 SDK
- Python 3.11+
- PostgreSQL 15+ (服务端)

### 客户端开发

```bash
cd client
npm install
npm run dev          # Vite HMR开发
npm run electron:dev # Electron + Vite开发
```

### 服务端开发

```bash
cd server
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### 审核面板开发

```bash
cd audit-panel
npm install
npm run dev
```

### 构建安装包

```powershell
# 构建所有原生模块
.\scripts\build-all.ps1

# 或分步构建
cd client
npm run build       # 构建Electron安装包
```

## 技术栈

- **桌面UI**: Electron 31 + React 18 + TypeScript + TailwindCSS
- **数据采集**: C# .NET 8 (WMI/EventLog/ETW) + C++20 (内核检测)
- **后端服务**: Python FastAPI + PostgreSQL + SQLAlchemy
- **安全**: Argon2id密码哈希, SQLCipher数据库加密, JWT认证, AES-256-GCM通信加密
- **打包**: electron-builder (NSIS安装包)

## 许可

本项目为专有软件，保留所有权利。
