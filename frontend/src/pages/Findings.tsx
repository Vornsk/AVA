import { useState, Fragment } from 'react'
import { ShieldAlert, ShieldCheck, AlertTriangle, ChevronRight, ChevronDown } from 'lucide-react'
import { usePoll, type Finding } from '../api'
import { Card, Badge, Empty, statusColor, severityColor } from '../components/ui'

// 심각도 정렬 순위 (high 먼저) + finding id 번호.
const SEV_RANK: Record<string, number> = { high: 0, medium: 1, low: 2, info: 3 }
const sevRank = (s: string) => SEV_RANK[s?.toLowerCase()] ?? 4
const idNum = (id: string) => parseInt(id.replace(/\D/g, ''), 10) || 0

// LLMVerdict — LLM 오탐 트리아지 판정 배지 + 근거 (FR-3.3).
function LLMVerdict({ f }: { f: Finding }) {
  const map: Record<string, { label: string; color: string }> = {
    real: { label: '실제 취약(LLM)', color: 'var(--red)' },
    false_positive: { label: '오탐 판정(LLM)', color: 'var(--muted)' },
    uncertain: { label: '판단 보류(LLM)', color: 'var(--amber)' },
  }
  const v = map[f.llm_verdict ?? ''] ?? { label: `LLM: ${f.llm_verdict}`, color: 'var(--muted)' }
  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="rounded px-1.5 py-0.5 text-[10px] font-semibold"
        style={{ color: v.color, border: `1px solid ${v.color}` }}>{v.label}</span>
      {f.llm_reason && <span className="text-[var(--muted)]">{f.llm_reason}</span>}
    </div>
  )
}

// EvidenceRow — 증적(FR-4.2): 재현 요청·증명 응답. 값은 서버에서 마스킹됨.
function EvidenceRow({ f }: { f: Finding }) {
  return (
    <tr className="border-t border-[var(--border)] bg-[var(--panel-2)]/40">
      <td colSpan={9} className="px-3 py-3">
        <div className="space-y-2 text-xs">
          {f.llm_verdict && <LLMVerdict f={f} />}
          {f.evidence && <div className="text-[var(--muted)]">{f.evidence}</div>}
          {f.request && (
            <div>
              <div className="mb-0.5 text-[10px] uppercase tracking-wide text-[var(--muted)]">재현 요청</div>
              <pre className="overflow-x-auto rounded border border-[var(--border)] bg-[var(--panel)] px-2 py-1 font-mono text-[11px]">{f.request}</pre>
            </div>
          )}
          {(f.response || f.resp_code) && (
            <div>
              <div className="mb-0.5 text-[10px] uppercase tracking-wide text-[var(--muted)]">
                증명 응답{f.resp_code ? ` · HTTP ${f.resp_code}` : ''} <span className="normal-case">(민감값 마스킹됨)</span>
              </div>
              <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded border border-[var(--border)] bg-[var(--panel)] px-2 py-1 font-mono text-[11px]">{f.response}</pre>
            </div>
          )}
        </div>
      </td>
    </tr>
  )
}

// 검토 상태머신 (FR-4.4) — 백엔드 transitions 미러.
const NEXT: Record<string, string[]> = {
  '신규': ['검토중', '오탐'],
  '검토중': ['확정', '오탐', '보류'],
  '보류': ['검토중'],
  '확정': ['보고'],
  '오탐': [], '보고': [],
}

// StatusCell — 상태 표시 + 다음 상태 전이(낙관적 락, FR-1.3). 409 충돌 시 알림.
function StatusCell({ f }: { f: Finding }) {
  const [busy, setBusy] = useState(false)
  const [conflict, setConflict] = useState(false)
  const next = NEXT[f.status] ?? []

  async function transition(to: string) {
    setBusy(true); setConflict(false)
    try {
      const res = await fetch(`/api/findings/${f.id}/status`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: to, version: f.version }),
      })
      if (res.status === 409) setConflict(true) // 다른 사용자가 먼저 수정 → 폴링이 곧 최신화
    } finally { setBusy(false) }
  }

  return (
    <div className="flex items-center gap-1.5">
      <span className="inline-flex items-center gap-1.5 text-xs font-medium" style={{ color: statusColor(f.status) }}>
        <span className="h-1.5 w-1.5 rounded-full" style={{ background: statusColor(f.status) }} />{f.status}
        <span className="text-[9px] text-[var(--muted)]">v{f.version}</span>
      </span>
      {next.length > 0 && (
        <select disabled={busy} value=""
                onChange={(e) => e.target.value && transition(e.target.value)}
                className="rounded border border-[var(--border)] bg-[var(--panel-2)] px-1 py-0.5 text-[10px]">
          <option value="">→</option>
          {next.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      )}
      {conflict && (
        <span className="inline-flex items-center gap-0.5 text-[10px]" style={{ color: 'var(--amber)' }} title="다른 사용자가 먼저 수정했습니다 — 최신으로 갱신됩니다">
          <AlertTriangle size={11} /> 충돌
        </span>
      )}
    </div>
  )
}

const SEVERITIES = ['high', 'medium', 'low', 'info'] as const
const STATUSES = ['신규', '검토중', '확정', '오탐', '보류', '보고']

export function Findings() {
  const { data } = usePoll<Finding[]>('/api/findings', 4000)
  const [open, setOpen] = useState<Set<string>>(new Set())
  const [hideLLMFP, setHideLLMFP] = useState(false)
  const [sevFilter, setSevFilter] = useState<string | null>(null)
  const [statusFilter, setStatusFilter] = useState('')

  const all = data ?? []
  const sevCounts: Record<string, number> = {}
  for (const f of all) { const s = f.severity?.toLowerCase(); sevCounts[s] = (sevCounts[s] ?? 0) + 1 }
  const llmFPCount = all.filter((f) => f.llm_verdict === 'false_positive').length

  let shown = all
  if (hideLLMFP) shown = shown.filter((f) => f.llm_verdict !== 'false_positive')
  if (sevFilter) shown = shown.filter((f) => f.severity?.toLowerCase() === sevFilter)
  if (statusFilter) shown = shown.filter((f) => f.status === statusFilter)
  // 심각도순(high 먼저) → 같은 심각도 내 최신순
  shown = [...shown].sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || idNum(b.id) - idNum(a.id))

  const toggle = (id: string) =>
    setOpen((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n })

  async function clearAll() {
    if (!confirm('도출 항목을 전체 삭제합니다. 되돌릴 수 없습니다. 계속할까요?')) return
    const res = await fetch('/api/findings/clear', { method: 'POST' })
    if (res.status === 403) alert('권한 없음: 도출 항목 초기화는 리더만 가능합니다.')
  }

  return (
    <Card
      title={`취약점 목록${data ? ` (${data.length})` : ''}`}
      icon={ShieldAlert}
      right={
        <div className="flex items-center gap-3">
          <div className="hidden items-center gap-1.5 text-[11px] text-[var(--muted)] md:flex">
            검토 상태: <span>신규 → 검토중 → 확정 · 오탐 · 보류 → 보고</span>
          </div>
          {llmFPCount > 0 && (
            <label className="flex cursor-pointer items-center gap-1.5 text-[11px] text-[var(--muted)]" title="LLM이 오탐으로 표시한 항목을 보기에서 숨김(데이터는 유지)">
              <input type="checkbox" checked={hideLLMFP} onChange={(e) => setHideLLMFP(e.target.checked)} />
              LLM 오탐 숨기기 ({llmFPCount})
            </label>
          )}
          {data && data.length > 0 && (
            <button onClick={clearAll}
              className="rounded border border-[var(--border)] px-2 py-1 text-[11px] text-[var(--muted)] transition-colors hover:border-[var(--red)] hover:text-[var(--red)]">
              전체 초기화
            </button>
          )}
        </div>
      }
    >
      {all.length > 0 && (
        <div className="mb-3 flex flex-wrap items-center gap-2 border-b border-[var(--border)] pb-3">
          {SEVERITIES.map((s) => sevCounts[s] ? (
            <button key={s} onClick={() => setSevFilter(sevFilter === s ? null : s)}
              className="rounded-md border px-2 py-0.5 text-xs font-semibold transition-colors"
              style={{ color: severityColor(s), borderColor: severityColor(s),
                       background: sevFilter === s ? `color-mix(in srgb, ${severityColor(s)} 16%, transparent)` : 'transparent',
                       opacity: sevFilter && sevFilter !== s ? 0.45 : 1 }}>
              {s} {sevCounts[s]}
            </button>
          ) : null)}
          <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}
                  className="rounded-md border border-[var(--border)] bg-[var(--panel-2)] px-2 py-1 text-xs">
            <option value="">전체 상태</option>
            {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          {(sevFilter || statusFilter) && (
            <button onClick={() => { setSevFilter(null); setStatusFilter('') }}
                    className="text-[11px] text-[var(--muted)] hover:text-[var(--text)]">필터 해제</button>
          )}
          <span className="ml-auto text-[11px] text-[var(--muted)]">{shown.length} / {all.length} 표시</span>
        </div>
      )}
      {all.length === 0 ? (
        <Empty icon={ShieldCheck}>아직 도출된 finding 이 없습니다. 스캔을 실행하면 여기에 표시됩니다.</Empty>
      ) : shown.length === 0 ? (
        <Empty icon={ShieldCheck}>필터 조건에 맞는 항목이 없습니다.</Empty>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase text-[var(--muted)]">
                <th className="pb-2 pr-1"></th>
                <th className="pb-2 pr-3">ID</th>
                <th className="pb-2 pr-3">Vulnerability</th>
                <th className="pb-2 pr-3">Severity</th>
                <th className="pb-2 pr-3">Target</th>
                <th className="pb-2 pr-3">Param</th>
                <th className="pb-2 pr-3">Detector</th>
                <th className="pb-2 pr-3">Check items</th>
                <th className="pb-2 pr-3">Status</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((f) => {
                const hasEv = !!(f.request || f.response || f.llm_verdict)
                const isOpen = open.has(f.id)
                return (
                <Fragment key={f.id}>
                <tr className={`border-t border-[var(--border)] align-top ${hasEv ? 'cursor-pointer hover:bg-[var(--panel-2)]/40' : ''}`}
                    onClick={hasEv ? () => toggle(f.id) : undefined}>
                  <td className="py-2 pl-1 pr-1 text-[var(--muted)]">
                    {hasEv && (isOpen ? <ChevronDown size={13} /> : <ChevronRight size={13} />)}
                  </td>
                  <td className="py-2 pr-3 font-mono text-xs">{f.id}</td>
                  <td className="py-2 pr-3 font-medium">{f.vuln}</td>
                  <td className="py-2 pr-3"><Badge text={f.severity} /></td>
                  <td className="py-2 pr-3">
                    <div className="font-mono text-xs">{f.host}</div>
                    <div className="font-mono text-xs text-[var(--muted)]">{f.method} {f.path}</div>
                  </td>
                  <td className="py-2 pr-3 font-mono text-xs">{f.param || '—'}</td>
                  <td className="py-2 pr-3">
                    <div className="text-xs">{f.detector}</div>
                    {f.vuln_def && <div className="text-[10px] text-[var(--muted)]">{f.vuln_def}</div>}
                  </td>
                  <td className="py-2 pr-3">
                    <div className="flex flex-wrap gap-1">
                      {(f.check_items ?? []).map((c) => <Badge key={c} text={c} color="var(--accent)" />)}
                      {(!f.check_items || f.check_items.length === 0) && <span className="text-xs text-[var(--muted)]">—</span>}
                    </div>
                  </td>
                  <td className="py-2 pr-3" onClick={(e) => e.stopPropagation()}><StatusCell f={f} /></td>
                </tr>
                {isOpen && hasEv && <EvidenceRow f={f} />}
                </Fragment>
              )})}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  )
}
