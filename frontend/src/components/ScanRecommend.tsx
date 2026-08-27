import { useEffect, useState } from 'react'
import { Sparkles, TriangleAlert, RotateCcw, Loader2 } from 'lucide-react'
import { apiPost, type RecommendResult, type DetectorInfo } from '../api'
import { Badge } from './ui'
import { useT } from '../i18n'

interface ScanRecommendProps {
  dets: DetectorInfo[]
  allowDestructive: boolean
  // null = 아직 스캔 시작 불가(추천 미조회 또는 검토 미완료). 검토 완료 시에만 대상별 계획 전달.
  onPlanChange: (plan: Record<string, string[]> | null) => void
}

// ScanRecommend — 엔드포인트별 AI 탐지기 추천(HITL). "추천 받기" → 대상별 테이블 검토·수정 →
// "검토했습니다" 체크가 있어야만 상위(ScanControl)로 계획을 전달해 스캔 시작을 허용한다.
export function ScanRecommend({ dets, allowDestructive, onPlanChange }: ScanRecommendProps) {
  const t = useT()
  const [rec, setRec] = useState<RecommendResult | null>(null)
  const [sel, setSel] = useState<Record<string, Set<string>>>({})
  const [reviewed, setReviewed] = useState(false)
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState('')

  async function fetchRec() {
    setLoading(true); setErr(''); setReviewed(false)
    try {
      const r = await apiPost<RecommendResult>('/api/scan/recommend', {})
      setRec(r)
      setSel(Object.fromEntries(r.items.map((i) => [i.key, new Set(i.recommended)])))
    } catch (e) { setErr(String(e)) } finally { setLoading(false) }
  }

  const toggle = (key: string, id: string) =>
    setSel((s) => {
      const n = new Set(s[key] ?? [])
      n.has(id) ? n.delete(id) : n.add(id)
      return { ...s, [key]: n }
    })

  // 검토 완료 상태에서만 계획을 상위로 전달 — 체크박스 조작·재추천 시 자동으로 다시 잠긴다(reviewed=false).
  useEffect(() => {
    if (!rec || !reviewed) { onPlanChange(null); return }
    const plan: Record<string, string[]> = {}
    for (const [k, s] of Object.entries(sel)) plan[k] = [...s]
    onPlanChange(plan)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reviewed])

  if (!rec) {
    return (
      <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed border-[var(--border)] py-6 text-center">
        <Sparkles size={18} className="text-[var(--muted)]" />
        <p className="text-xs text-[var(--muted)]">{t('scan.ai.intro')}</p>
        <button onClick={fetchRec} disabled={loading}
                className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold disabled:opacity-50"
                style={{ background: 'var(--accent)', color: 'var(--accent-fg)' }}>
          {loading ? <Loader2 size={13} className="animate-spin" /> : <Sparkles size={13} />}
          {loading ? t('scan.ai.fetching') : t('scan.ai.fetchButton')}
        </button>
        {err && <div className="text-xs" style={{ color: 'var(--red)' }}>{err}</div>}
      </div>
    )
  }

  return (
    <div>
      {rec.degraded && (
        <div className="mb-2 flex items-start gap-1.5 rounded-md border border-[var(--border)] bg-[var(--panel-2)] p-2 text-xs" style={{ color: 'var(--amber)' }}>
          <TriangleAlert size={13} className="mt-0.5 shrink-0" />
          <span>{t('scan.ai.degraded')}{rec.reason ? ` — ${rec.reason}` : ''}</span>
        </div>
      )}
      <div className="mb-2 flex items-center justify-between">
        <span className="text-[11px] text-[var(--muted)]">
          {t('scan.ai.itemCount', { n: rec.items.length })} · {rec.source === 'llm' ? t('scan.ai.sourceLLM', { provider: rec.provider ?? '' }) : t('scan.ai.sourceFallback')}
        </span>
        <button onClick={fetchRec} disabled={loading} className="inline-flex items-center gap-1 text-[11px] text-[var(--muted)] underline disabled:opacity-50">
          {loading ? <Loader2 size={11} className="animate-spin" /> : <RotateCcw size={11} />}
          {loading ? t('scan.ai.fetching') : t('scan.ai.refetch')}
        </button>
      </div>

      <div className="max-h-80 space-y-1.5 overflow-y-auto">
        {rec.items.map((it) => {
          const chips = dets.filter((d) => !d.destructive || allowDestructive)
          return (
            <div key={it.key} className="rounded-lg border border-[var(--border)] bg-[var(--panel-2)] p-2">
              <div className="mb-1 flex flex-wrap items-center gap-1.5">
                <span className="font-mono text-xs">{(it.methods ?? []).join('/')} {it.path}</span>
                {it.fallback ? <Badge text={t('scan.ai.fallbackBadge')} color="var(--amber)" /> : <Badge text={t('scan.ai.aiBadge')} color="var(--blue)" />}
                <span className="ml-auto text-[11px] text-[var(--muted)]">{(sel[it.key]?.size ?? 0)}/{chips.length}</span>
              </div>
              {it.reason && <p className="mb-1.5 text-[11px] text-[var(--muted)]">{it.reason}</p>}
              <div className="flex flex-wrap gap-1.5">
                {chips.map((d) => {
                  const on = sel[it.key]?.has(d.id) ?? false
                  return (
                    <label key={d.id} className="flex cursor-pointer items-center gap-1 rounded border px-1.5 py-0.5 text-[11px]"
                           style={{ borderColor: on ? 'var(--accent)' : 'var(--border)', background: on ? 'var(--panel)' : 'transparent' }}
                           title={d.name}>
                      <input type="checkbox" checked={on} onChange={() => { toggle(it.key, d.id); setReviewed(false) }} className="h-3 w-3" />
                      <span className="font-mono">{d.id}</span>
                      {d.destructive && <Badge text="D" color="var(--red)" />}
                    </label>
                  )
                })}
              </div>
            </div>
          )
        })}
      </div>

      <label className="mt-3 flex cursor-pointer items-center gap-1.5 border-t border-[var(--border)] pt-3 text-xs">
        <input type="checkbox" checked={reviewed} onChange={(e) => setReviewed(e.target.checked)} />
        {t('scan.ai.reviewedLabel')}
      </label>
    </div>
  )
}
