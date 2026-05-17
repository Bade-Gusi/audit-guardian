# 部署文档

## 服务端部署

### 环境要求
- Ubuntu 22.04+ / Windows Server 2022+
- Python 3.11+
- PostgreSQL 15+
- Nginx (反向代理)

### 安装步骤

```bash
# 1. 克隆项目
git clone <repo-url> /opt/audit-guardian
cd /opt/audit-guardian/server

# 2. 创建虚拟环境
python -m venv venv
source venv/bin/activate

# 3. 安装依赖
pip install -r requirements.txt

# 4. 配置环境变量
cat > .env << EOF
DATABASE_URL=postgresql+asyncpg://audit:password@localhost:5432/audit_guardian
JWT_SECRET_KEY=your-secure-random-key-here
REPORT_ENCRYPTION_KEY=your-32-byte-encryption-key
EOF

# 5. 初始化数据库
alembic upgrade head

# 6. 启动服务 (使用systemd或docker)
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### Nginx 配置

```nginx
server {
    listen 443 ssl;
    server_name audit-api.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    client_max_body_size 50m;
}
```

## 客户端部署

### 环境要求
- Windows 10/11 64位
- .NET 8 Runtime
- 管理员权限 (部分采集功能需要)

### 安装
1. 运行 `赛审卫士-Setup-x.x.x.exe` (使用 electron-builder 构建)
2. 默认安装到 `C:\Program Files\赛审卫士`
3. 首次运行需要输入 License

### 构建安装包

```bash
cd client
npm install
npm run electron:build
# 输出在 release/ 目录
```

## 审核面板部署

```bash
cd audit-panel
npm install
npm run build
# 静态文件在 dist/ 目录，部署到 Nginx
```
