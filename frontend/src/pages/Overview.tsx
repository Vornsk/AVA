import { Radar, Layers, FolderGit2, Laptop, ShieldCheck, ShieldOff, ArrowRight, Circle, Inbox } from 'lucide-react'
import { usePoll, type Stats, type ScanRun, type Project } from '../api'
import { Card, Badge, Dot, Empty } from '../components/ui'
import type { Page } from '../components/Sidebar'
import { useT } from '../i18n'

export function Overview({ onNav }: { onNav?: (p: Page) => void }) {
  const t = useT()
  const { data: stats } = usePoll<Stats>('/api/stats', 4000)
  const { data: runs } = usePoll<ScanRun[]>('/api/scanruns', 4000)
  const { data: proj } = usePoll<Project>('/api/active-project', 8000)
  const { data: projects } = usePoll<Project[]>('/api/projects', 8000)
  const primary = proj?.name || stats?.scope?.[0] || '—'
  const riskC = stats?.risk_profile === 'high' ? 'var(--red)'
    : stats?.risk_profile === 'medium' ? 'var(--amber)'
    : stats?.risk_profile === 'low' ? 'var(--blue)' : 'var(--muted)'

  return (
    <div className="grid gap-5 lg:grid-cols-[2fr_1fr]">
      <div className="space-y-5">
        <div className="rounded-xl border border-[var(--border)] bg-[var(--panel)] shadow-[var(--shadow)] overflow-hidden">
          <div className="p-5">
            <div className="flex items-start justify-between">
              <div>
                <div className="flex items-center gap-2.5">
                  <h2 className="text-xl font-bold tracking-tight">{primary}</h2>
                  {proj && <span className="rounded-md border border-[var(--border)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--muted)]">{proj.id}</span>}
                  <span className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium"
                        style={{ color: 'var(--green)', background: 'color-mix(in srgb, var(--green) 15%, transparent)' }}>
                    <Circle size={7} fill="currentColor" /> {t('overview.live')}
                  </span>
                </div>
                <p className="mt-1 font-mono text-xs text-[var(--muted)]">
                  {proj?.main_url || 'MITM proxy'} · {(stats?.schemes ?? []).join(' / ') || t('overview.allSchemes')}
                </p>
              </div>
              <div className="flex flex-col items-end gap-1">
                <span className="rounded-lg border border-[var(--border)] bg-[var(--panel-2)] px-2.5 py-1 text-xs font-medium text-[var(--muted)]">
                  LLM · {stats?.llm_provider ?? '—'}
                </span>
                {/* 판단 불능은 눈에 띄어야 한다 — 이게 안 보여서 가드레일이 죽은 줄 몰랐다 (이슈 #56) */}
                {stats?.llm_health?.degraded && (
                  <span className="rounded-lg px-2.5 py-1 text-xs font-semibold"
                        style={{ background: 'color-mix(in srgb, var(--red) 18%, transparent)', color: 'var(--red)' }}
                        title={stats.llm_health.reason}>
                    {t('overview.llmDegraded', { policy: stats.llm_health.policy })}
                  </span>
                )}
                {proj && <span className="text-[10px] text-[var(--muted)]">created {proj.created}{projects && projects.length > 1 ? ` · ${projects.length} projects` : ''}</span>}
              </div>
            </div>
          </div>
          <div className="grid grid-cols-2 divide-x divide-[var(--border)] border-t border-[var(--border)] sm:grid-cols-4">
            <Meta label={t('overview.meta.scope')} value={`${stats?.hosts ?? '—'} hosts`} />
            <Meta label={t('overview.meta.attackSurface')} value={`${stats?.endpoints ?? '—'} eps`} />
            <Meta label={t('overview.meta.findings')} value={String(stats?.findings ?? '—')} color={stats?.findings ? 'var(--red)' : undefined} />
            <Meta label={t('overview.meta.riskProfile')} value={<span style={{ color: riskC }}>{stats?.risk_profile ?? '—'}</span>} />
          </div>
        </div>

        <Card
          title={t('overview.recentRuns')} icon={Radar}
          right={onNav && (
            <button onClick={() => onNav('scan')}
                    className="inline-flex items-center gap-1 text-xs font-medium text-[var(--accent)] hover:opacity-80">
              {t('overview.viewAll')} <ArrowRight size={13} />
            </button>
          )}
        >
          {!runs || runs.length === 0 ? (
            <Empty icon={Inbox}>{t('overview.noScans')}</Empty>
          ) : (
            <table className="w-full text-sm [font-variant-numeric:tabular-nums]">
              <thead>
                <tr className="eyebrow text-left">
                  <th className="pb-2 font-semibold">{t('overview.col.run')}</th><th className="pb-2 font-semibold">{t('overview.col.detectors')}</th>
                  <th className="pb-2 font-semibold">{t('overview.col.status')}</th><th className="pb-2 font-semibold">{t('overview.col.progress')}</th>
                  <th className="pb-2 font-semibold">{t('overview.col.findings')}</th>
                </tr>
              </thead>
              <tbody>
                {[...runs].reverse().slice(0, 6).map((r) => (
                  <tr key={r.id} className="border-t border-[var(--border)]">
                    <td className="py-2.5 font-mono text-xs">{r.id}</td>
                    <td className="py-2.5 text-xs text-[var(--muted)]">{(r.detectors ?? []).join(', ') || (r.safe_mode ? 'safe-mode' : '—')}</td>
                    <td className="py-2.5"><Dot text={r.status} /></td>
                    <td className="py-2.5 text-[var(--muted)]">{r.done}/{r.total}</td>
                    <td className="py-2.5 font-semibold">{r.findings}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>

      <div className="space-y-5">
        <Card title={t('overview.topology')} icon={Layers}>
          <div className="space-y-1">
            <TopoRow icon={Layers} name={t('overview.topo.shared')} sub={t('overview.topo.sharedSub', { n: stats?.schemes?.length ?? 0 })} status={t('overview.topo.loaded')} />
            <TopoRow icon={FolderGit2} name={t('overview.topo.project')} sub={t('overview.topo.projectSub', { n: stats?.rules ?? 0 })} status={t('overview.topo.loaded')} />
            <TopoRow icon={Laptop} name={t('overview.topo.local')} sub={t('overview.topo.localSub', { provider: stats?.llm_provider ?? '—' })}
                     status={stats?.llm_health?.degraded ? t('overview.topo.degraded') : t('overview.topo.verified')} />
          </div>
        </Card>

        <Card title={t('overview.caCert')} icon={stats?.ca_trusted ? ShieldCheck : ShieldOff}>
          <CertRow label={t('overview.cert.trustStore')} ok={!!stats?.ca_trusted} okText={t('overview.cert.trusted')} offText={t('overview.cert.untrusted')} />
          <div className="mt-3 flex items-center justify-between border-t border-[var(--border)] pt-3 text-xs text-[var(--muted)]">
            <span>{t('overview.cert.mobile')}</span><span>{t('overview.cert.notConfigured')}</span>
          </div>
        </Card>

        <Card title={t('overview.guardrails')} icon={ShieldCheck}>
          <div className="flex items-center justify-between text-sm">
            <span className="text-[var(--muted)]">{t('overview.gr.safeMode')}</span>
            <Badge text={stats?.safe_mode ? 'On' : 'Off'} color={stats?.safe_mode ? 'var(--amber)' : 'var(--muted)'} dot />
          </div>
          <div className="mt-2.5 flex items-center justify-between text-sm">
            <span className="text-[var(--muted)]">{t('overview.gr.detectorsAvailable')}</span>
            <span className="font-semibold [font-variant-numeric:tabular-nums]">{stats?.detectors ?? '—'}</span>
          </div>
        </Card>
      </div>
    </div>
  )
}

function Meta({ label, value, color }: { label: string; value: React.ReactNode; color?: string }) {
  return (
    <div className="px-4 py-3.5">
      <div className="eyebrow">{label}</div>
      <div className="mt-1 text-lg font-bold [font-variant-numeric:tabular-nums]" style={color ? { color } : undefined}>{value}</div>
    </div>
  )
}

function TopoRow({ icon: Icon, name, sub, status }: { icon: any; name: string; sub: string; status: string }) {
  return (
    <div className="flex items-center gap-3 rounded-lg px-2 py-2.5 hover:bg-[var(--panel-2)]">
      <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg text-[var(--accent)]"
            style={{ background: 'color-mix(in srgb, var(--accent) 12%, transparent)' }}>
        <Icon size={16} />
      </span>
      <div className="min-w-0 flex-1">
        <div className="text-sm font-medium">{name}</div>
        <div className="truncate text-xs text-[var(--muted)]">{sub}</div>
      </div>
      <span className="inline-flex items-center gap-1.5 text-xs font-medium" style={{ color: 'var(--green)' }}>
        <Circle size={7} fill="currentColor" />{status}
      </span>
    </div>
  )
}

function CertRow({ label, ok, okText, offText }: { label: string; ok: boolean; okText: string; offText: string }) {
  const c = ok ? 'var(--green)' : 'var(--red)'
  return (
    <div>
      <div className="flex items-center justify-between text-sm">
        <span className="font-medium">{label}</span>
        <span className="inline-flex items-center gap-1.5 text-xs font-medium" style={{ color: c }}>
          <Circle size={7} fill="currentColor" />{ok ? okText : offText}
        </span>
      </div>
      <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-[var(--panel-2)]">
        <div className="h-full rounded-full" style={{ width: ok ? '100%' : '30%', background: c }} />
      </div>
    </div>
  )
}
