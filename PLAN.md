# 赛审卫士 · 反作弊与行为审计系统 — 实施计划

## 一、技术选型（最终方案）

| 层级 | 技术 | 理由 |
|------|------|------|
| **桌面UI** | Electron 30 + React 18 + TypeScript | 丰富的UI生态，Fluent/Material 设计, 动画流畅 |
| **数据采集层** | C# .NET 8 (WMI/EventLog/ETW) + C++ (内核检测) | C#快速覆盖90%需求，C++处理底层hook检测 |
| **本地存储** | SQLite + SQLCipher (加密) | 零配置、加密存储 |
| **后端API** | Python FastAPI + PostgreSQL | 快速开发、强类型(Pydantic)、异步支持 |
| **审核面板** | React 18 + TypeScript (独立Web应用) | 与客户端复用组件，专业审核视图 |
| **安全加固** | ConfuserEx (.NET) + VMProtect (C++ DLL) + asar加密 (Electron) | 多层防护 |
| **状态管理** | Zustand | 轻量、TypeScript友好 |
| **UI框架** | TailwindCSS + Framer Motion + Radix UI | 现代UI、动画、无样式的可访问组件 |
| **打包** | electron-builder | Windows NSIS安装包 |

---

## 二、项目结构

```
赛审卫士/
├── client/                          # Electron桌面客户端
│   ├── electron/
│   │   ├── main.ts                  # 主进程入口
│   │   ├── preload.ts               # 预加载脚本 (contextBridge)
│   │   └── ipc/
│   │       ├── hardware.ts          # IPC: 硬件采集
│   │       ├── eventLogs.ts         # IPC: 事件日志
│   │       ├── fileActivity.ts      # IPC: 文件活动
│   │       ├── scan.ts              # IPC: 反作弊扫描
│   │       └── report.ts            # IPC: 报告生成
│   ├── src/
│   │   ├── App.tsx
│   │   ├── main.tsx
│   │   ├── components/
│   │   │   ├── layout/
│   │   │   │   ├── Sidebar.tsx
│   │   │   │   ├── Header.tsx
│   │   │   │   └── MainLayout.tsx
│   │   │   ├── dashboard/
│   │   │   │   ├── DashboardPage.tsx
│   │   │   │   ├── StatusCard.tsx
│   │   │   │   ├── RiskOverview.tsx
│   │   │   │   └── QuickActions.tsx
│   │   │   ├── hardware/
│   │   │   │   ├── HardwarePage.tsx
│   │   │   │   ├── HardwareCard.tsx
│   │   │   │   ├── HardwareDetail.tsx
│   │   │   │   └── ChangeHistory.tsx
│   │   │   ├── timeline/
│   │   │   │   ├── TimelinePage.tsx
│   │   │   │   ├── TimelineItem.tsx
│   │   │   │   ├── TimelineFilter.tsx
│   │   │   │   └── TimelineChart.tsx
│   │   │   ├── scan/
│   │   │   │   ├── ScanPage.tsx
│   │   │   │   ├── ScanProgress.tsx
│   │   │   │   ├── ScanResultCard.tsx
│   │   │   │   └── SignatureManager.tsx
│   │   │   ├── report/
│   │   │   │   ├── ReportPage.tsx
│   │   │   │   ├── ReportPreview.tsx
│   │   │   │   ├── ReportExport.tsx
│   │   │   │   └── UploadDialog.tsx
│   │   │   ├── auth/
│   │   │   │   ├── LoginPage.tsx
│   │   │   │   └── VirtualKeyboard.tsx
│   │   │   └── common/
│   │   │       ├── StatusBadge.tsx
│   │   │       ├── LoadingSpinner.tsx
│   │   │       ├── PasswordInput.tsx
│   │   │       └── ConfirmDialog.tsx
│   │   ├── hooks/
│   │   │   ├── useHardware.ts
│   │   │   ├── useEventLogs.ts
│   │   │   ├── useScan.ts
│   │   │   └── useReport.ts
│   │   ├── stores/
│   │   │   ├── appStore.ts
│   │   │   ├── hardwareStore.ts
│   │   │   ├── timelineStore.ts
│   │   │   └── scanStore.ts
│   │   ├── types/
│   │   │   ├── hardware.ts
│   │   │   ├── event.ts
│   │   │   ├── scan.ts
│   │   │   └── report.ts
│   │   ├── utils/
│   │   │   ├── formatters.ts
│   │   │   ├── encryption.ts
│   │   │   └── api.ts
│   │   └── styles/
│   │       ├── globals.css
│   │       └── theme.ts
│   ├── native/                      # 原生采集模块
│   │   ├── HardwareCollector/       # C# .NET 项目
│   │   ├── EventLogCollector/       # C# .NET 项目
│   │   ├── FileActivityReader/      # C# .NET 项目
│   │   └── KernelDetector/          # C++ 项目
│   ├── resources/
│   │   └── signatures/             # 特征库 (JSON)
│   │       ├── process_blacklist.json
│   │       └── driver_blacklist.json
│   ├── package.json
│   ├── tsconfig.json
│   ├── tailwind.config.ts
│   ├── vite.config.ts
│   └── electron-builder.yml
│
├── server/                          # FastAPI 后端
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py
│   │   ├── config.py
│   │   ├── database.py
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   ├── auth.py
│   │   │   ├── cases.py
│   │   │   ├── reports.py
│   │   │   └── admin.py
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── user.py
│   │   │   ├── case.py
│   │   │   └── report.py
│   │   ├── schemas/
│   │   │   ├── __init__.py
│   │   │   ├── auth.py
│   │   │   ├── case.py
│   │   │   └── report.py
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   ├── auth_service.py
│   │   │   ├── case_service.py
│   │   │   └── report_service.py
│   │   └── utils/
│   │       ├── encryption.py
│   │       └── license.py
│   ├── alembic/
│   │   └── versions/
│   ├── requirements.txt
│   └── Dockerfile
│
├── audit-panel/                     # 审核员Web面板
│   ├── src/
│   │   ├── App.tsx
│   │   ├── components/
│   │   │   ├── CaseList.tsx
│   │   │   ├── CaseDetail.tsx
│   │   │   ├── ReportViewer.tsx
│   │   │   ├── MarkPanel.tsx
│   │   │   └── CompareView.tsx
│   │   └── ...
│   ├── package.json
│   └── vite.config.ts
│
├── docs/
│   ├── architecture.md
│   ├── deployment.md
│   ├── user-manual.md
│   └── api-reference.md
│
└── README.md
```

---

## 三、数据库设计

### 3.1 本地 SQLite (客户端缓存)

```sql
-- 硬件信息快照
CREATE TABLE hardware_snapshot (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  category TEXT NOT NULL,       -- cpu/gpu/motherboard/disk/network/ram
  property TEXT NOT NULL,
  value TEXT NOT NULL,
  is_spoofed INTEGER DEFAULT 0, -- 是否被篡改
  captured_at TEXT NOT NULL
);

-- 硬件变动历史
CREATE TABLE hardware_changes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  category TEXT NOT NULL,
  property TEXT NOT NULL,
  old_value TEXT,
  new_value TEXT,
  changed_at TEXT NOT NULL,
  change_type TEXT NOT NULL       -- added/removed/modified
);

-- 事件日志缓存
CREATE TABLE event_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  log_name TEXT NOT NULL,         -- Security/System/Application
  event_id INTEGER NOT NULL,
  timestamp TEXT NOT NULL,
  level TEXT NOT NULL,            -- Information/Warning/Error
  source TEXT,
  category INTEGER,
  user_name TEXT,
  description TEXT,
  raw_xml TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

-- 文件活动记录
CREATE TABLE file_activities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  activity_type TEXT NOT NULL,    -- created/modified/deleted/renamed/accessed
  file_path TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  process_name TEXT,
  source TEXT,                    -- shellbags/prefetch/recent/jumplist
  detail TEXT
);

-- 扫描结果
CREATE TABLE scan_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_type TEXT NOT NULL,        -- process/service/driver/kernel_hook
  match_type TEXT NOT NULL,       -- name/hash/signature/behavior
  match_value TEXT,
  severity TEXT NOT NULL,         -- low/medium/high/critical
  description TEXT,
  found_at TEXT NOT NULL,
  is_running INTEGER DEFAULT 0,
  file_path TEXT,
  recommendation TEXT
);

-- 报告缓存
CREATE TABLE reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL,
  case_name TEXT NOT NULL,
  machine_name TEXT,
  report_data TEXT NOT NULL,      -- JSON 完整报告
  encrypted INTEGER DEFAULT 1,
  uploaded INTEGER DEFAULT 0,
  upload_url TEXT
);

-- 配置
CREATE TABLE config (
  key TEXT PRIMARY KEY,
  value TEXT
);
```

### 3.2 服务端 PostgreSQL

```sql
-- 用户
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'auditor',  -- admin/auditor/supervisor
  display_name TEXT,
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  last_login TIMESTAMPTZ
);

-- 案件
CREATE TABLE cases (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_name TEXT NOT NULL,
  machine_name TEXT,
  hardware_id TEXT,               -- 硬件指纹hash
  license_key TEXT,
  status TEXT DEFAULT 'pending',   -- pending/reviewing/confirmed/cleared
  priority TEXT DEFAULT 'normal',  -- low/normal/high/critical
  assigned_to UUID REFERENCES users(id),
  created_by UUID REFERENCES users(id),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 报告
CREATE TABLE reports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id UUID REFERENCES cases(id) ON DELETE CASCADE,
  version INTEGER DEFAULT 1,
  report_data JSONB NOT NULL,     -- 完整报告JSON
  summary JSONB,                  -- 摘要信息
  risk_score REAL DEFAULT 0,       -- 0-100 风险评分
  total_items INTEGER DEFAULT 0,
  suspicious_items INTEGER DEFAULT 0,
  high_risk_items INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 审核标记
CREATE TABLE review_marks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  report_id UUID REFERENCES reports(id) ON DELETE CASCADE,
  item_type TEXT NOT NULL,         -- event/process/file/hardware
  item_hash TEXT NOT NULL,         -- 指向报告JSON中的具体项
  verdict TEXT NOT NULL,           -- suspicious/confirmed/benign/false_positive
  comment TEXT,
  marked_by UUID REFERENCES users(id),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 审核日志
CREATE TABLE audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id),
  action TEXT NOT NULL,
  target_type TEXT,
  target_id TEXT,
  detail JSONB,
  ip_address INET,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- License
CREATE TABLE licenses (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  license_key TEXT UNIQUE NOT NULL,
  hardware_id TEXT,
  is_active BOOLEAN DEFAULT true,
  issued_to TEXT,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
```

---

## 四、API 端点设计

### 认证
| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/auth/login` | 登录，返回JWT |
| POST | `/api/auth/refresh` | 刷新Token |
| GET | `/api/auth/me` | 当前用户信息 |

### 案件
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/cases` | 案件列表（分页、筛选） |
| GET | `/api/cases/{id}` | 案件详情 |
| PATCH | `/api/cases/{id}` | 更新案件状态/分配 |
| POST | `/api/cases` | 创建案件（上传报告时） |

### 报告
| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/reports` | 上传加密报告 |
| GET | `/api/reports/{id}` | 获取报告详情 |
| GET | `/api/reports/{id}/decrypt` | 获取解密后的报告（需权限） |
| GET | `/api/reports/{id}/compare/{other_id}` | 两份报告对比 |

### 审核标记
| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/reports/{id}/marks` | 添加审核标记 |
| GET | `/api/reports/{id}/marks` | 获取审核标记 |
| DELETE | `/api/reports/{id}/marks/{mark_id}` | 删除标记 |

### 管理
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/admin/users` | 用户管理 |
| POST | `/api/admin/license/generate` | 生成License |
| GET | `/api/admin/stats` | 系统统计 |

---

## 五、报告数据格式 (JSON Schema)

```json
{
  "report_version": "1.0",
  "generated_at": "2026-05-17T10:30:00Z",
  "collector_version": "1.0.0",
  "case": {
    "name": "比赛名称-选手姓名",
    "machine_name": "DESKTOP-ABC123"
  },
  "hardware_fingerprint": {
    "machine_hash": "sha256-of-combined-hardware",
    "items": [
      {
        "category": "cpu",
        "properties": [
          {"name": "ProcessorName", "value": "Intel Core i7-12700H", "is_spoofed": false},
          {"name": "Cores", "value": "14", "is_spoofed": false}
        ]
      }
    ],
    "change_history": [
      {"property": "disk:SN1234", "change": "removed", "at": "2026-05-15T...", "detail": "disk was removed at 2026-05-15 ..."}
    ],
    "spoof_detection": {
      "has_spoofed": false,
      "details": []
    }
  },
  "timeline": {
    "total_events": 15234,
    "time_range": {"start": "2026-05-10T00:00:00Z", "end": "2026-05-17T10:30:00Z"},
    "events": [
      {
        "timestamp": "2026-05-16T14:23:10Z",
        "type": "process_run",
        "source": "event_log",
        "severity": "info",
        "description": "Process started: C:\\Users\\...\\game.exe",
        "detail": {"pid": 1234, "command_line": "\"game.exe\" --launch", "parent_pid": 5678}
      }
    ],
    "summary": {
      "by_type": {"process_run": 230, "file_create": 45, "usb_plug": 3},
      "by_date": {"2026-05-16": 234, "2026-05-17": 56}
    }
  },
  "scan_results": {
    "scanned_at": "2026-05-17T10:30:00Z",
    "total_checks": 150,
    "findings": [
      {
        "type": "process",
        "severity": "high",
        "description": "Suspicious process: cheat_engine.exe",
        "matched_rule": "process_name:cheat_engine*",
        "found_at": "2026-05-16T20:15:00Z",
        "status": "was_running_but_uninstalled"
      }
    ],
    "kernel_checks": {
      "ssdt_hooked": false,
      "unusual_callbacks": [],
      "filter_drivers": []
    },
    "summary": {
      "critical": 0,
      "high": 2,
      "medium": 5,
      "low": 12
    }
  },
  "risk_assessment": {
    "overall_score": 15.5,
    "level": "low",
    "flags": [
      {"category": "software", "item": "Cheat Engine was once installed", "severity": "medium"},
      {"category": "file", "item": "Modified game executable detected", "severity": "high"}
    ],
    "recommendations": [
      "Full reinstall of competition environment recommended"
    ]
  }
}
```

---

## 六、数据采集管道设计

```
┌─────────────────────────────────────────────────────┐
│                  Electron Main Process              │
│                                                      │
│  ipcMain.handle('collect:hardware')                  │
│      → spawn Collector.exe hardware                  │
│      → stdout JSON → parse → return                  │
│                                                      │
│  ipcMain.handle('collect:eventlogs')                 │
│      → spawn Collector.exe eventlogs --since 7d     │
│      → progress via stdout lines                     │
│                                                      │
│  ipcMain.handle('scan:anticheat')                    │
│      → spawn KernelDetector.exe --deep               │
│      → load signatures from resources/signatures/   │
└──────────────────────┬──────────────────────────────┘
                       │ IPC (contextBridge)
┌──────────────────────▼──────────────────────────────┐
│              React Renderer Process                 │
│                                                      │
│  hooks → stores → components                        │
│  Dashboard / Timeline / Scan / Report               │
└─────────────────────────────────────────────────────┘
```

**Native采集器通信协议**:
- Electron主进程通过 `child_process.spawn()` 启动.NET/C++控制台程序
- 采集器通过 **stdout** 输出 JSON Lines (每行一个JSON对象)
- 采集器通过 **stderr** 输出进度信息 `{"progress": 45, "status": "scanning processes..."}`
- 采集完成输出 `{"complete": true, "summary": {...}}` 后退出
- 超时30秒无响应则强制终止
- 所有采集器通过 Electron 的 `getNetworkFetch()` 验证自身签名

---

## 七、UI组件树与数据流

```
App
├── LoginPage (未认证时)
│   ├── PasswordInput (密码明文切换 / 虚拟键盘)
│   ├── LicenseValidator (硬件绑定验证)
│   └── UnlockButton
│
└── MainLayout (已认证)
    ├── Sidebar
    │   ├── NavItem: 仪表盘 (Dashboard)
    │   ├── NavItem: 硬件信息 (Hardware)
    │   ├── NavItem: 行为时间线 (Timeline)
    │   ├── NavItem: 反作弊扫描 (Scan)
    │   ├── NavItem: 报告管理 (Report)
    │   └── NavItem: 设置 (Settings)
    │
    ├── Header
    │   ├── SearchBar
    │   ├── NotificationBadge
    │   └── UserMenu
    │
    └── Content (React Router)
        ├── DashboardPage
        │   ├── StatusCard (硬件状态 / 日志数量 / 风险项 / 报告状态)
        │   ├── RiskOverview (最近风险项列表)
        │   └── QuickActions (一键扫描 / 生成报告)
        │
        ├── HardwarePage
        │   ├── HardwareCard[] (按类别: CPU/GPU/主板/硬盘/网卡/内存)
        │   ├── HardwareDetail (展开详情)
        │   └── ChangeHistory (硬件变动时间线)
        │
        ├── TimelinePage
        │   ├── TimelineFilter (按类型/等级/时间)
        │   ├── TimelineChart (事件分布直方图)
        │   └── TimelineItem[] (事件流)
        │
        ├── ScanPage
        │   ├── ScanProgress (扫描进度条)
        │   ├── ScanResultCard[] (按严重度分组)
        │   └── SignatureManager (管理特征库)
        │
        ├── ReportPage
        │   ├── ReportPreview (HTML预览)
        │   ├── ReportExport (PDF/HTML导出)
        │   └── UploadDialog (上传到审核服务器)
        │
        └── SettingsPage
            ├── PasswordChange
            ├── LicenseInfo
            └── About
```

**数据流**: React Component → Hook (useHardware/useScan) → Store (Zustand) → IPC call → Native Collector

---

## 八、安全策略

| 层级 | 措施 |
|------|------|
| **启动** | 启动密码 (Argon2id) + 硬件绑定License (RSA签名) |
| **网络** | TLS 1.3 + 载荷AES-256-GCM加密 + 请求签名 |
| **本地存储** | SQLCipher (AES-256-CBC) + 数据库密码派生自硬件指纹 |
| **代码保护** | Electron asar加密 + .NET ConfuserEx + C++ VMProtect |
| **反调试** | IsDebuggerPresent / NtQueryInformationProcess / 时间差检测 / 反dump |
| **通信** | IPC白名单验证, native模块签名校验 |
| **报告** | 报告文件AES-256加密, 传输和存储全程加密 |

---

## 九、实施阶段

### Phase 1: 项目骨架 (7-10天)
1. 搭建 Electron + React 项目 (Vite + TypeScript + TailwindCSS)
2. 实现基本路由和Layout组件
3. 配置 electron-builder 打包
4. 搭建 FastAPI 服务器骨架 + 数据库初始化
5. 实现登录页面 UI

### Phase 2: 数据采集核心 (10-14天)
1. C# HardwareCollector - CPU/GPU/主板/硬盘/网卡信息
2. C# EventLogCollector - Windows事件日志读取
3. C# FileActivityReader - Prefetch/Shellbags/Recent/JumpList
4. Electron IPC 集成 native 采集器
5. 硬件信息页面 UI
6. 时间线页面 UI

### Phase 3: 反作弊扫描 (7-10天)
1. C++ KernelDetector - SSDT Hook / 内核回调 / 过滤驱动检测
2. 进程/服务/驱动黑名单匹配
3. 特征库 JSON 格式定义
4. 扫描引擎与Electron集成
5. 扫描页面 UI

### Phase 4: 报告与远程审核 (7-10天)
1. 报告聚合生成逻辑
2. HTML/PDF导出 (Puppeteer)
3. 报告加密与上传
4. FastAPI 案件/报告管理API
5. 审核员Web面板 (audit-panel)
6. 风险评分算法

### Phase 5: 安全加固与发布 (5-7天)
1. 启动密码 + License验证
2. 虚拟键盘
3. 代码混淆/加壳
4. 反调试保护
5. 打包安装程序
6. 部署文档 + 用户手册

---

## 十、风险项颜色体系

| 等级 | 颜色 (HEX) | 用途 |
|------|-----------|------|
| 正常/安全 | `#22C55E` (绿) | 硬件正常、无风险项 |
| 可疑/注意 | `#EAB308` (黄) | 非常规但未确认恶意 |
| 高危 | `#EF4444` (红) | 确认的风险项 |
| 未知/信息 | `#6B7280` (灰) | 普通信息条目 |
| 处理中 | `#3B82F6` (蓝) | 扫描/加载进行中 |
