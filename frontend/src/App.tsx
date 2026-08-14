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
import { useT, type MsgKey } from './i18n'

// 헤더 문구는 i18n 키로 보관하고 렌더 시 t() 로 해석한다.
const META: Record<Page, { title: MsgKey; subtitle: MsgKey; el: (p: { onNav: (p: Page) => void }) => JSX.Element }> = {
  overview: { title: 'page.overview.title', subtitle: 'page.overview.subtitle', el: Overview },
  projects: { title: 'page.projects.title', subtitle: 'page.projects.subtitle', el: Projects },
  recon: { title: 'page.recon.title', subtitle: 'page.recon.subtitle', el: Recon },
  scan: { title: 'page.scan.title', subtitle: 'page.scan.subtitle', el: Scan },
  findings: { title: 'page.findings.title', subtitle: 'page.findings.subtitle', el: Findings },
  coverage: { title: 'page.coverage.title', subtitle: 'page.coverage.subtitle', el: Coverage },
  report: { title: 'page.report.title', subtitle: 'page.report.subtitle', el: Report },
  reverify: { title: 'page.reverify.title', subtitle: 'page.reverify.subtitle', el: Reverify },
  advisor: { title: 'page.advisor.title', subtitle: 'page.advisor.subtitle', el: Advisor },
  audit: { title: 'page.audit.title', subtitle: 'page.audit.subtitle', el: Audit },
  users: { title: 'page.users.title', subtitle: 'page.users.subtitle', el: Users },
}

export default function App() {
  const t = useT()
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
        <Topbar title={t(m.title)} subtitle={t(m.subtitle)} />
        <main className="flex-1 overflow-auto p-6">
          <Body onNav={setPage} />
        </main>
      </div>
    </div>
  )
}
