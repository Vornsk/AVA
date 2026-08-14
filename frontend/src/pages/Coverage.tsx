import { ListChecks, Download } from 'lucide-react'
import { usePoll, type CoverageReport, type SchemeCoverage, type ItemStatus } from '../api'
import { Card, Badge, Empty, Dot, statusColor } from '../components/ui'
import { useT } from '../i18n'

// 상태 우선순위(조치할 것부터): 취약 → 미점검 → 미지원 → 양호.
const STATUS_RANK: Record<string, number> = {
  '취약': 0, '미점검': 1, '미지원(도구없음)': 2, '미지원(수동)': 3, '양호': 4, '해당없음': 5,
}
const rank = (s: string) => STATUS_RANK[s] ?? 9

// 상태 → 4개 분포 버킷(세그먼트 바·요약용).
function buckets(items: ItemStatus[]) {
  const b = { 취약: 0, 미점검: 0, 미지원: 0, 양호: 0 }
  for (const it of items) {
    if (it.status === '취약') b.취약++
    else if (it.status === '양호') b.양호++
    else if (it.status === '미점검') b.미점검++
    else b.미지원++
  }
  return b
}
const SEGMENTS = [
  { k: '취약', c: 'var(--red)' },
  { k: '미점검', c: 'var(--amber)' },
  { k: '미지원', c: 'var(--muted)' },
  { k: '양호', c: 'var(--green)' },
] as const

// StatusBar — 양호/취약/미점검/미지원 비율 세그먼트 바 + 건수 범례.
function StatusBar({ items }: { items: ItemStatus[] }) {
  const b = buckets(items)
  const total = items.length || 1
  return (
    <div>
      <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-[var(--panel-2)]">
        {SEGMENTS.map((x) => b[x.k] > 0 && (
          <div key={x.k} style={{ width: `${(b[x.k] / total) * 100}%`, background: x.c }} title={`${x.k} ${b[x.k]}`} />
        ))}
      </div>
      <div className="mt-1.5 flex flex-wrap gap-3 text-[11px]">
        {SEGMENTS.map((x) => b[x.k] > 0 && (
          <span key={x.k} className="inline-flex items-center gap-1 text-[var(--muted)]">
            <span className="h-2 w-2 rounded-full" style={{ background: x.c }} />{x.k} <b className="text-[var(--text)]">{b[x.k]}</b>
          </span>
        ))}
      </div>
    </div>
  )
}

export function Coverage() {
  const t = useT()
  const { data } = usePoll<CoverageReport>('/api/coverage', 5000)
  const schemes = data?.schemes ?? []

  if (schemes.length === 0) return <Card title={t('coverage.title')} icon={ListChecks}><Empty>{t('coverage.empty')}</Empty></Card>

  const allItems = schemes.flatMap((s) => s.items)

  return (
    <div className="space-y-5">
      {/* 전체 요약 */}
      <Card title={t('coverage.overallTitle')} icon={ListChecks}
            right={<a href="/coverage.xlsx"
              className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold"
              style={{ background: 'var(--accent)', color: 'var(--accent-fg)' }}>
              <Download size={14} /> {t('coverage.exportXlsx')}
            </a>}>
        <p className="mb-3 text-xs text-[var(--muted)]">
          {t('coverage.summaryLead')}<span className="font-medium text-[var(--text)]">{t('coverage.summaryEmphasis')}</span>{t('coverage.summaryTail')}
        </p>
        <StatusBar items={allItems} />
      </Card>
      {schemes.map((s) => <SchemeBlock key={s.scheme} s={s} />)}
    </div>
  )
}

function SchemeBlock({ s }: { s: SchemeCoverage }) {
  const t = useT()
  const items = [...s.items].sort((a, b) => rank(a.status) - rank(b.status)) // 취약·미점검 먼저
  return (
    <Card
      title={<span className="flex items-center gap-2">{s.scheme}
        <span className="text-xs font-normal text-[var(--muted)]">{t('coverage.itemCount', { count: s.total })}</span></span>}
      right={
        <div className="flex items-center gap-2 text-xs">
          <Badge text={`취약 ${s.vulnerable}`} color="var(--red)" />
          <Badge text={`${t('coverage.automatable')} ${s.automatable}/${s.total}`} color="var(--blue)" />
        </div>
      }
    >
      <div className="mb-3">
        <StatusBar items={s.items} />
      </div>

      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-xs uppercase text-[var(--muted)]">
            <th className="pb-2 pr-3">{t('coverage.colItem')}</th><th className="pb-2 pr-3">{t('coverage.colVulnerability')}</th>
            <th className="pb-2 pr-3">{t('coverage.colDetectors')}</th><th className="pb-2 pr-3">{t('coverage.colFindings')}</th>
            <th className="pb-2 pr-3">{t('coverage.colStatus')}</th>
          </tr>
        </thead>
        <tbody>
          {items.map((it) => (
            <tr key={it.check_item.id} className="border-t border-[var(--border)]"
                style={it.status === '취약' ? { background: 'color-mix(in srgb, var(--red) 8%, transparent)' } : undefined}>
              <td className="py-2 pr-3 font-mono text-xs">
                {it.check_item.id}
                {typeof it.check_item.risk === 'number' && (
                  <span className="ml-1 text-[10px] text-[var(--muted)]">R{it.check_item.risk}</span>
                )}
              </td>
              <td className="py-2 pr-3">{it.vuln_name}</td>
              <td className="py-2 pr-3 text-xs text-[var(--muted)]">
                {(it.detectors ?? []).join(', ') || '—'}
              </td>
              <td className="py-2 pr-3">{it.findings || '—'}</td>
              <td className="py-2 pr-3"><Dot text={it.status} color={statusColor(it.status)} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  )
}
