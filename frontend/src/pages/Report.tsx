import { FileSpreadsheet, Download, Inbox, ListChecks, FileSearch } from 'lucide-react'
import { usePoll } from '../api'
import { Card, Empty, Badge, severityColor } from '../components/ui'
import { useT } from '../i18n'

interface ReportRow {
  no: number; target: string; main_url: string; vuln: string; path: string
  url: string; param: string; desc: string; count: number; payload: string; remark: string
  severity: string
}
interface ReportData { headers: string[]; rows: ReportRow[] }

interface EvidenceRow {
  no: number; vuln: string; severity: string; url: string; param: string
  request: string; resp_code: number; response: string
}
interface EvidenceData { headers: string[]; rows: EvidenceRow[] }

const SEV_RANK: Record<string, number> = { high: 0, medium: 1, low: 2, info: 3 }
const sevRank = (s: string) => SEV_RANK[(s || '').toLowerCase()] ?? 9
const sevLabel: Record<string, string> = { high: '높음', medium: '중간', low: '낮음', info: '정보' }
const sevKr = (s: string) => sevLabel[(s || '').toLowerCase()] ?? (s || '—')

function SevBadge({ s }: { s: string }) {
  return <Badge text={sevKr(s)} color={severityColor(s)} />
}

export function Report() {
  const t = useT()
  const { data } = usePoll<ReportData>('/api/report', 5000)
  const { data: ev } = usePoll<EvidenceData>('/api/evidence', 5000)
  const rows = data?.rows ?? []
  const evRows = ev?.rows ?? []

  // 취약점 유형별 그룹 (심각도 높은 유형 먼저).
  const groupsMap = new Map<string, ReportRow[]>()
  for (const r of rows) {
    const g = groupsMap.get(r.vuln) ?? []
    g.push(r); groupsMap.set(r.vuln, g)
  }
  const groups = [...groupsMap.entries()]
    .map(([vuln, rs]) => ({ vuln, rows: rs, sev: rs.reduce((m, r) => Math.min(m, sevRank(r.severity)), 9) }))
    .sort((a, b) => a.sev - b.sev || b.rows.length - a.rows.length)

  return (
    <div className="space-y-5">
      {/* 1) 산출물 허브 + 요약 */}
      <Card title={t('report.hub.title')} icon={FileSpreadsheet}
            right={
              <div className="flex items-center gap-2">
                <a href="/report.xlsx?lang=ko" className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold"
                   style={{ background: 'var(--accent)', color: 'var(--accent-fg)' }} title={t('report.hub.xlsxFindings.tooltip')}>
                  <Download size={14} /> {t('report.hub.xlsxFindings.btn')}
                </a>
                <a href="/report.xlsx?lang=en" className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border)] px-3 py-1.5 text-xs font-semibold"
                   title={t('report.hub.findingsEnTooltip')}>
                  <Download size={14} /> {t('report.hub.findingsEnBtn')}
                </a>
                <a href="/coverage.xlsx?lang=ko" className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border)] px-3 py-1.5 text-xs font-semibold"
                   title={t('report.hub.xlsxCoverage.tooltip')}>
                  <ListChecks size={14} /> {t('report.hub.xlsxCoverage.btn')}
                </a>
                <a href="/coverage.xlsx?lang=en" className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border)] px-3 py-1.5 text-xs font-semibold"
                   title={t('report.hub.coverageEnTooltip')}>
                  <ListChecks size={14} /> {t('report.hub.coverageEnBtn')}
                </a>
              </div>
            }>
        <p className="mb-3 text-xs text-[var(--muted)]">
          <b className="text-[var(--text)]">{t('report.hub.desc.b1')}</b>{t('report.hub.desc.s1')}<b className="text-[var(--text)]">{t('report.hub.desc.b2')}</b>{t('report.hub.desc.s2')}<b className="text-[var(--text)]">{t('report.hub.desc.b3')}</b>{t('report.hub.desc.s3')}
        </p>
        {rows.length === 0 ? (
          <span className="text-xs text-[var(--muted)]">{t('report.hub.emptyFindings')}</span>
        ) : (
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-[var(--muted)]">{t('report.hub.summary.pre')}<b className="text-[var(--text)]">{rows.length}</b>{t('report.hub.summary.mid')}<b className="text-[var(--text)]">{evRows.length}</b>{t('report.hub.summary.post')}</span>
            {groups.map((g) => (
              <span key={g.vuln} className="inline-flex items-center gap-1 rounded-full border border-[var(--border)] px-2 py-0.5 text-[11px]">
                <span className="h-2 w-2 rounded-full" style={{ background: severityColor(['high','medium','low','info'][g.sev] ?? 'info') }} />
                {g.vuln} <b>{g.rows.length}</b>
              </span>
            ))}
          </div>
        )}
      </Card>

      {/* 2) 도출리스트 — 유형별 그룹 + 심각도 */}
      <Card title={t('report.export.title', { count: rows.length })} icon={FileSpreadsheet}>
        {rows.length === 0 ? (
          <Empty icon={Inbox}>{t('report.export.empty')}</Empty>
        ) : (
          <div className="space-y-4">
            {groups.map((g) => (
              <div key={g.vuln}>
                <div className="mb-1.5 flex items-center gap-2">
                  <SevBadge s={['high','medium','low','info'][g.sev] ?? 'info'} />
                  <span className="text-sm font-semibold">{g.vuln}</span>
                  <span className="text-xs text-[var(--muted)]">{t('report.export.group.count', { count: g.rows.length })}</span>
                </div>
                <div className="overflow-x-auto rounded-lg border border-[var(--border)]">
                  <table className="w-full text-xs [font-variant-numeric:tabular-nums]">
                    <thead>
                      <tr className="eyebrow text-left">
                        <th className="whitespace-nowrap px-2 py-1.5 font-semibold">NO</th>
                        <th className="px-2 py-1.5 font-semibold">{t('report.export.col.target')}</th>
                        <th className="px-2 py-1.5 font-semibold">{t('report.export.col.foundUrl')}</th>
                        <th className="px-2 py-1.5 font-semibold">{t('report.export.col.param')}</th>
                        <th className="px-2 py-1.5 font-semibold">{t('report.export.col.desc')}</th>
                        <th className="px-2 py-1.5 font-semibold">{t('report.export.col.remark')}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {g.rows.map((r) => (
                        <tr key={r.no} className="border-t border-[var(--border)] align-top">
                          <td className="px-2 py-1.5">{r.no}</td>
                          <td className="px-2 py-1.5 font-medium">{r.target}</td>
                          <td className="px-2 py-1.5 font-mono text-[var(--muted)]">{r.path}</td>
                          <td className="px-2 py-1.5 font-mono">{r.param || '—'}</td>
                          <td className="max-w-[280px] px-2 py-1.5 text-[var(--muted)]">{r.desc}</td>
                          <td className="whitespace-nowrap px-2 py-1.5 text-[var(--muted)]">{r.remark}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* 3) 증적 (FR-4.2) 미리보기 */}
      <Card title={t('report.evidence.title', { count: evRows.length })} icon={FileSearch}>
        <p className="mb-3 text-xs text-[var(--muted)]">
          {t('report.evidence.desc.pre')}<b className="text-[var(--text)]">{t('report.evidence.desc.b1')}</b>{t('report.evidence.desc.mid')}<b className="text-[var(--text)]">{t('report.evidence.desc.b2')}</b>{t('report.evidence.desc.post')}
        </p>
        {evRows.length === 0 ? (
          <Empty icon={Inbox}>{t('report.evidence.empty')}</Empty>
        ) : (
          <div className="space-y-2">
            {evRows.map((e) => (
              <details key={e.no} className="rounded-lg border border-[var(--border)] px-3 py-2">
                <summary className="flex cursor-pointer items-center gap-2 text-sm">
                  <SevBadge s={e.severity} />
                  <span className="font-medium">{e.vuln}</span>
                  <span className="font-mono text-xs text-[var(--muted)]">{e.url}{e.param ? ` · ${e.param}` : ''}</span>
                  <span className="ml-auto font-mono text-[11px] text-[var(--muted)]">HTTP {e.resp_code || '—'}</span>
                </summary>
                <div className="mt-2 space-y-2">
                  <div>
                    <div className="eyebrow mb-1">{t('report.evidence.reqLabel')}</div>
                    <pre className="overflow-x-auto rounded bg-[var(--panel-2)] p-2 font-mono text-[11px] leading-relaxed">{e.request || '—'}</pre>
                  </div>
                  <div>
                    <div className="eyebrow mb-1">{t('report.evidence.respLabel')}</div>
                    <pre className="max-h-60 overflow-auto rounded bg-[var(--panel-2)] p-2 font-mono text-[11px] leading-relaxed">{e.response || '—'}</pre>
                  </div>
                </div>
              </details>
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}
