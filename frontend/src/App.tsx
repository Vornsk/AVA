import { useEffect, useState } from 'react'
import { Sidebar, type Page } from './components/Sidebar'
import { Topbar } from './components/Topbar'
import { Login } from './pages/Login'
import { Overview } from './pages/Overview'
import { Projects } from './pages/Projects'
import { Recon } from './pages/Recon'
import { Scan } from './pages/Scan'
import { Findings } from './pages/Findings'
import { Coverage } from './pages/Coverage'
import { Report } from './pages/Report'
import { Reverify } from './pages/Reverify'
import { Advisor } from './pages/Advisor'
import { Audit } from './pages/Audit'
import { Users } from './pages/Users'

const META: Record<Page, { title: string; subtitle: string; el: (p: { onNav: (p: Page) => void }) => JSX.Element }> = {
  overview: { title: 'Project Workspace', subtitle: '진단 대상과 현황 요약', el: Overview },
  projects: { title: 'Projects', subtitle: '프로젝트 생성·전환 및 접근 관리', el: Projects },
  recon: { title: '대상 파악', subtitle: '엔드포인트·요청 판단·스코프·인증 현황', el: Recon },
  scan: { title: '자동화 진단', subtitle: '진단 실행·탐지기·가드레일·페이로드', el: Scan },
  findings: { title: '취약점 목록', subtitle: '도출된 취약점과 검토 상태 관리', el: Findings },
  coverage: { title: '점검 커버리지', subtitle: '점검항목 대비 진단 결과 — 양호·취약·미점검', el: Coverage },
  report: { title: '도출리스트', subtitle: '표준 엑셀 양식(11개 컬럼)으로 내보내기', el: Report },
  reverify: { title: '이행점검', subtitle: '조치 여부 재점검 및 스캔 간 변화 비교', el: Reverify },
  advisor: { title: 'Rule Advisor', subtitle: 'LLM 판단 기록과 룰 추천', el: Advisor },
  audit: { title: '감사 로그', subtitle: '모든 변경 이력 — 누가·언제·무엇을', el: Audit },
  users: { title: '사용자 관리', subtitle: '계정 목록 및 생성 — 리더 전용', el: Users },
}

export default function App() {
  const [page, setPage] = useState<Page>('overview')
  const [authed, setAuthed] = useState<boolean | null>(null)

  useEffect(() => {
    fetch('/api/me').then((r) => setAuthed(r.ok)).catch(() => setAuthed(false))
  }, [])

  if (authed === null) return <div className="h-full" />
  if (!authed) return <Login onSuccess={() => setAuthed(true)} />

  const m = META[page]
  const Body = m.el
  return (
    <div className="flex h-full">
      <Sidebar page={page} onNav={setPage} />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar title={m.title} subtitle={m.subtitle} />
        <main className="flex-1 overflow-auto p-6">
          <Body onNav={setPage} />
        </main>
      </div>
    </div>
  )
}
