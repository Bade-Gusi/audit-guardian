import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { ShieldCheck } from 'lucide-react'

function CaseListPage() {
  return (
    <div className="min-h-screen bg-surface-50">
      <header className="bg-white border-b border-surface-200 px-6 h-16 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ShieldCheck className="w-7 h-7 text-primary-600" />
          <h1 className="text-lg font-bold text-surface-800">赛审卫士 · 审核面板</h1>
        </div>
        <div className="flex items-center gap-4">
          <span className="text-sm text-surface-500">审核员: 管理员</span>
          <button className="px-3 py-1.5 text-sm bg-surface-100 hover:bg-surface-200 rounded-lg">退出</button>
        </div>
      </header>
      <main className="p-6">
        <div className="mb-6">
          <h2 className="text-xl font-semibold text-surface-800">案件列表</h2>
          <p className="text-sm text-surface-500 mt-1">管理所有已上传的审计报告</p>
        </div>
        <div className="bg-white rounded-xl border border-surface-200 p-8 text-center text-surface-400">
          <p>暂无案件，等待客户端上传报告</p>
        </div>
      </main>
    </div>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Navigate to="/cases" replace />} />
        <Route path="/cases" element={<CaseListPage />} />
      </Routes>
    </BrowserRouter>
  )
}
