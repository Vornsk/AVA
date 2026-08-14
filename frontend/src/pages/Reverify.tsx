import { useEffect, useState } from 'react'
import { RotateCcw, CheckCircle2, XCircle, HelpCircle, Inbox, GitCompareArrows, Plus, Minus, Play } from 'lucide-react'
import { usePoll, apiPost, apiGet, type ReverifyRun, type ScanRun, type ScanDiff, type Finding } from '../api'
import { Card, Dot, Badge, Empty } from '../components/ui'
import { useT } from '../i18n'

// verdict 색상·정렬: 미조치/신규발생을 위로.
const VERDICT_COLOR: Record<string, string> = {
  '조치완료': 'var(--green)', '미조치': 'var(--red)', '부분조치': 'var(--amber)',
  '신규발생': 'var(--red)', '미확인': 'var(--muted)',
}
const vColor = (v: string) => VERDICT_COLOR[v] ?? 'var(--muted)'
const VERDICT_RANK: Record<string, number> = { '미조치': 0, '신규발생': 0, '부분조치': 1, '미확인': 2, '조치완료': 3 }
const vRank = (v: string) => VERDICT_RANK[v] ?? 9

// 이행상태(finding.reverify_status) — 미설정은 '미점검'으로 집계.
const REV = { '조치완료': 'var(--green)', '미조치': 'var(--red)', '부분조치': 'var(--amber)', '신규발생': 'var(--red)', '미점검': 'var(--muted)' } as const

export function Reverify() {
  const t = useT()
  const { data } = usePoll<ReverifyRun[]>('/api/reverify', 4000)
  const runs = [...(data ?? [])].reverse()

  return (
    <div className="space-y-5">
      <ReverifyControl />
      <DiffCard />

      {runs.length === 0 ? (
        <Card title={t('reverify.section')} icon={RotateCcw}>
          <Empty icon={Inbox}>
            {t('reverify.empty')}
          </Empty>
        </Card>
      ) : runs.map((run) => (
        <Card
          key={run.id}
          icon={RotateCcw}
          title={
            <span className="flex items-center gap-2">
              {run.id}
              <span className="text-xs font-normal text-[var(--muted)]">
                source: {run.source} · {run.time}
              </span>
            </span>
          }
          right={
            <div className="flex items-center gap-2 text-xs">
              <Kpi icon={CheckCircle2} n={run.fixed} label="조치완료" color="var(--green)" />
              <Kpi icon={XCircle} n={run.open} label="미조치" color="var(--red)" />
              <Kpi icon={HelpCircle} n={run.unknown} label="미확인" color="var(--muted)" />
            </div>
          }
        >
          {/* 조치율 바 */}
          <div className="mb-3">
            <div className="mb-1 flex justify-between text-xs text-[var(--muted)]">
              <span>{t('reverify.remediationRate')}</span>
              <span>{run.total ? Math.round((run.fixed / run.total) * 100) : 0}% ({run.fixed}/{run.total})</span>
            </div>
            <div className="flex h-2 w-full overflow-hidden rounded-full bg-[var(--panel-2)]">
              <div style={{ width: pct(run.fixed, run.total), background: 'var(--green)' }} />
              <div style={{ width: pct(run.open, run.total), background: 'var(--red)' }} />
              <div style={{ width: pct(run.unknown, run.total), background: 'var(--muted)' }} />
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-sm [font-variant-numeric:tabular-nums]">
              <thead>
                <tr className="eyebrow text-left">
                  <th className="pb-2 pr-3 font-semibold">{t('reverify.col.finding')}</th>
                  <th className="pb-2 pr-3 font-semibold">{t('reverify.col.vulnerability')}</th>
                  <th className="pb-2 pr-3 font-semibold">{t('reverify.col.target')}</th>
                  <th className="pb-2 pr-3 font-semibold">{t('reverify.col.detector')}</th>
                  <th className="pb-2 pr-3 font-semibold">{t('reverify.col.verdict')}</th>
                  <th className="pb-2 pr-3 font-semibold">{t('reverify.col.detail')}</th>
                </tr>
              </thead>
              <tbody>
                {[...run.results].sort((a, b) => vRank(a.verdict) - vRank(b.verdict)).map((r) => (
                  <tr key={r.finding_id} className="border-t border-[var(--border)]"
                      style={vRank(r.verdict) === 0 ? { background: 'color-mix(in srgb, var(--red) 8%, transparent)' } : undefined}>
                    <td className="py-2.5 pr-3 font-mono text-xs">{r.finding_id}</td>
                    <td className="py-2.5 pr-3 font-medium">{r.vuln}</td>
                    <td className="py-2.5 pr-3 font-mono text-xs text-[var(--muted)]">{r.target}</td>
                    <td className="py-2.5 pr-3 text-xs">{r.detector}</td>
                    <td className="py-2.5 pr-3"><Dot text={r.verdict} color={vColor(r.verdict)} /></td>
                    <td className="py-2.5 pr-3 text-xs text-[var(--muted)]">{r.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      ))}
    </div>
  )
}

// ReverifyControl — 이행점검 실행(FR-5.2/5.3) + 전체 이행 현황 요약.
function ReverifyControl() {
  const t = useT()
  const { data: findings } = usePoll<Finding[]>('/api/findings', 5000)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')

  const fs = findings ?? []
  const targets = fs.filter((f) => f.status !== '오탐') // 오탐 제외가 재점검 대상
  // 전체 이행 현황(reverify_status, 미설정=미점검).
  const counts: Record<string, number> = { '조치완료': 0, '미조치': 0, '부분조치': 0, '신규발생': 0, '미점검': 0 }
  for (const f of targets) counts[f.reverify_status || '미점검'] = (counts[f.reverify_status || '미점검'] ?? 0) + 1
  const total = targets.length

  async function run() {
    setBusy(true); setMsg('')
    try {
      const r = await apiPost<ReverifyRun>('/api/reverify', {})
      setMsg(t('reverify.runResult', { id: r.id, fixed: r.fixed, open: r.open, unknown: r.unknown }))
    } catch (e) { setMsg(t('reverify.runFail') + ': ' + e) } finally { setBusy(false) }
  }

  return (
    <Card title={t('reverify.runTitle')} icon={RotateCcw}
          right={<span className="text-[11px] text-[var(--muted)]">{t('reverify.targetsPre')}<b className="text-[var(--text)]">{total}</b>{t('reverify.targetsPost')}<span className="opacity-70">{t('reverify.exclFp')}</span></span>}>
      <div className="flex flex-wrap items-center gap-3">
        <button onClick={run} disabled={busy || total === 0}
                className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold disabled:opacity-50"
                style={{ background: 'var(--accent)', color: 'var(--accent-fg)' }}>
          <Play size={13} /> {busy ? t('reverify.running') : t('reverify.runBtn')}
        </button>
        <span className="text-[11px] text-[var(--muted)]">{t('reverify.desc')}</span>
        {msg && <span className="text-[11px]" style={{ color: 'var(--green)' }}>{msg}</span>}
        {total === 0 && <span className="text-[11px]" style={{ color: 'var(--amber)' }}>{t('reverify.noTargets')}</span>}
      </div>

      {total > 0 && (
        <div className="mt-3">
          <div className="mb-1.5 text-xs text-[var(--muted)]">{t('reverify.overallStatus', { total })}</div>
          <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-[var(--panel-2)]">
            {(Object.keys(REV) as (keyof typeof REV)[]).map((k) => counts[k] > 0 && (
              <div key={k} style={{ width: `${(counts[k] / total) * 100}%`, background: REV[k] }} title={`${k} ${counts[k]}`} />
            ))}
          </div>
          <div className="mt-1.5 flex flex-wrap gap-3 text-[11px]">
            {(Object.keys(REV) as (keyof typeof REV)[]).map((k) => counts[k] > 0 && (
              <span key={k} className="inline-flex items-center gap-1 text-[var(--muted)]">
                <span className="h-2 w-2 rounded-full" style={{ background: REV[k] }} />{k} <b className="text-[var(--text)]">{counts[k]}</b>
              </span>
            ))}
          </div>
        </div>
      )}
    </Card>
  )
}

function Kpi({ icon: Icon, n, label, color }: { icon: any; n: number; label: string; color: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-md px-2 py-1 font-medium"
          style={{ color, background: `color-mix(in srgb, ${color} 13%, transparent)` }}>
      <Icon size={13} /> {n} <span className="text-[var(--muted)]">{label}</span>
    </span>
  )
}

function pct(n: number, total: number) { return total ? `${(n / total) * 100}%` : '0%' }

// DiffCard — 두 ScanRun 간 공격면 diff (FR-5.4): 신규/소멸 finding.
function DiffCard() {
  const t = useT()
  const { data: runs } = usePoll<ScanRun[]>('/api/scanruns', 5000)
  const ids = (runs ?? []).map((r) => r.id)
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [diff, setDiff] = useState<ScanDiff | null>(null)

  // 기본값: 최신 두 개(이전→최신) 자동 선택.
  useEffect(() => {
    if (ids.length >= 2 && !from && !to) {
      setFrom(ids[ids.length - 2])
      setTo(ids[ids.length - 1])
    }
  }, [ids.join(',')])

  useEffect(() => {
    if (from && to) {
      apiGet<ScanDiff>(`/api/scan-diff?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`)
        .then(setDiff).catch(() => setDiff(null))
    }
  }, [from, to])

  const sel = 'rounded-lg border border-[var(--border)] bg-[var(--panel-2)] px-2 py-1 text-xs font-mono'

  return (
    <Card
      title={t('reverify.diff.title')}
      icon={GitCompareArrows}
      right={
        <div className="flex items-center gap-2 text-xs">
          <select className={sel} value={from} onChange={(e) => setFrom(e.target.value)}>
            <option value="">{t('reverify.diff.fromOpt')}</option>
            {ids.map((id) => <option key={id} value={id}>{id}</option>)}
          </select>
          <span className="text-[var(--muted)]">→</span>
          <select className={sel} value={to} onChange={(e) => setTo(e.target.value)}>
            <option value="">{t('reverify.diff.toOpt')}</option>
            {ids.map((id) => <option key={id} value={id}>{id}</option>)}
          </select>
        </div>
      }
    >
      {ids.length < 2 ? (
        <Empty icon={GitCompareArrows}>{t('reverify.diff.needTwo')}</Empty>
      ) : !diff ? (
        <div className="py-4 text-center text-sm text-[var(--muted)]">{t('reverify.diff.selectFromTo')}</div>
      ) : (
        <div>
          <div className="mb-3 flex items-center gap-2 text-xs">
            <Badge text={t('reverify.diff.newBadge', { n: diff.added.length })} color="var(--red)" />
            <Badge text={t('reverify.diff.goneBadge', { n: diff.removed.length })} color="var(--green)" />
            <Badge text={t('reverify.diff.commonBadge', { n: diff.common })} color="var(--muted)" />
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <DiffList title={t('reverify.diff.added')} icon={Plus} color="var(--red)" items={diff.added} />
            <DiffList title={t('reverify.diff.removed')} icon={Minus} color="var(--green)" items={diff.removed} />
          </div>
        </div>
      )}
    </Card>
  )
}

function DiffList({ title, icon: Icon, color, items }: { title: string; icon: any; color: string; items: ScanDiff['added'] }) {
  const t = useT()
  return (
    <div className="rounded-lg border border-[var(--border)] bg-[var(--panel-2)] p-3">
      <div className="mb-2 flex items-center gap-1.5 text-xs font-semibold" style={{ color }}>
        <Icon size={13} /> {title} ({items.length})
      </div>
      {items.length === 0 ? (
        <div className="text-xs text-[var(--muted)]">{t('common.none')}</div>
      ) : (
        <div className="space-y-1">
          {items.map((f, i) => (
            <div key={i} className="flex items-center gap-2 text-xs">
              <span className="font-medium">{f.vuln}</span>
              <span className="font-mono text-[var(--muted)]">{f.method} {f.host}{f.path}</span>
              {f.param && <span className="font-mono text-[10px] text-[var(--muted)]">?{f.param}</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
