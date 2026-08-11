import { LayoutDashboard, FolderKanban, Network, Radar, ShieldAlert, ListChecks, FileSpreadsheet, RotateCcw, BrainCircuit, ScrollText, Users, type LucideIcon } from 'lucide-react'
import { AvaMark } from './AvaMark'

export type Page = 'overview' | 'projects' | 'recon' | 'scan' | 'findings' | 'coverage' | 'report' | 'reverify' | 'advisor' | 'audit' | 'users'

const GROUPS: { group: string; items: { id: Page; label: string; icon: LucideIcon }[] }[] = [
  { group: '작업공간', items: [
    { id: 'overview', label: '개요', icon: LayoutDashboard },
    { id: 'projects', label: '프로젝트', icon: FolderKanban },
  ]},
  { group: '진단', items: [
    { id: 'recon', label: '정찰', icon: Network },
    { id: 'scan', label: '스캔', icon: Radar },
  ]},
  { group: '결과', items: [
    { id: 'findings', label: '취약점', icon: ShieldAlert },
    { id: 'coverage', label: '커버리지', icon: ListChecks },
    { id: 'report', label: '리포트', icon: FileSpreadsheet },
    { id: 'reverify', label: '이행점검', icon: RotateCcw },
  ]},
  { group: '인텔리전스', items: [
    { id: 'advisor', label: '룰 제안', icon: BrainCircuit },
    { id: 'audit', label: '감사', icon: ScrollText },
  ]},
  { group: '관리', items: [
    { id: 'users', label: '사용자', icon: Users },
  ]},
]

export function Sidebar({ page, onNav }: { page: Page; onNav: (p: Page) => void }) {
  return (
    <aside className="flex w-60 shrink-0 flex-col border-r border-[var(--border)] bg-[var(--panel)]">
      <div className="flex items-center gap-2.5 px-5 py-[18px] border-b border-[var(--border)]">
        <div className="grid h-9 w-9 place-items-center rounded-xl shadow-[var(--shadow)]"
             style={{ background: 'linear-gradient(135deg, var(--accent), color-mix(in srgb, var(--accent) 60%, #000))', color: 'var(--accent-fg)' }}>
          <AvaMark size={20} />
        </div>
        <div className="min-w-0">
          <div className="text-[17px] font-extrabold leading-none tracking-[0.02em]">AVA</div>
          <div className="mt-0.5 text-[9px] font-semibold uppercase leading-[1.3] tracking-[0.1em] text-[var(--muted)]">Automated Vulnerability Assessment</div>
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto px-3 py-3">
        {GROUPS.map((g) => (
          <div key={g.group} className="mb-3">
            <div className="eyebrow px-2 pb-1.5">{g.group}</div>
            {g.items.map((n) => {
              const active = page === n.id
              const Icon = n.icon
              return (
                <button
                  key={n.id}
                  onClick={() => onNav(n.id)}
                  className="group relative mb-0.5 flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors"
                  style={active
                    ? { background: 'color-mix(in srgb, var(--accent) 14%, transparent)', color: 'var(--text)' }
                    : { color: 'var(--muted)' }}
                >
                  {active && <span className="absolute left-0 top-1.5 bottom-1.5 w-[3px] rounded-full" style={{ background: 'var(--accent)' }} />}
                  <Icon size={17} strokeWidth={2} style={{ color: active ? 'var(--accent)' : 'currentColor' }} />
                  <span className="flex-1 text-left">{n.label}</span>
                </button>
              )
            })}
          </div>
        ))}
      </nav>

      <div className="flex items-center justify-between px-4 py-3.5 border-t border-[var(--border)]">
        <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-[var(--muted)]">
          <span className="h-1.5 w-1.5 rounded-full" style={{ background: 'var(--green)' }} />
          읽기전용
        </span>
        <span className="text-[11px] text-[var(--muted)]">PoC</span>
      </div>
    </aside>
  )
}
