import { useState } from 'react'
import { BrainCircuit, Lightbulb, TriangleAlert, ShieldCheck, Check, Zap } from 'lucide-react'
import { usePoll, apiPost, type LLMDecision, type RuleCandidate, type Rule } from '../api'
import { Card, Badge, Empty } from '../components/ui'

export function Advisor() {
  const { data } = usePoll<LLMDecision[]>('/api/llm-decisions', 4000)
  const { data: cands } = usePoll<RuleCandidate[]>('/api/rule-candidates', 5000)
  const { data: activeRules } = usePoll<Rule[]>('/api/rules', 5000)
  const [adopted, setAdopted] = useState<Set<string>>(new Set())
  const [busy, setBusy] = useState('')
  const [err, setErr] = useState('')

  async function adopt(c: RuleCandidate) {
    setBusy(c.signature); setErr('')
    try {
      await apiPost('/api/rules/adopt', { signature: c.signature })
      setAdopted((s) => new Set(s).add(c.signature))
    } catch (e) { setErr(String(e)) } finally { setBusy('') }
  }

  return (
    <div className="space-y-5">
      {/* 1) 룰 추천 후보 + 채택 */}
      <Card
        title={`룰 추천 후보${cands ? ` — ${cands.length}` : ''}`}
        icon={Lightbulb}
        right={<span className="text-[11px] text-[var(--muted)]">제안만 — 검토·승인 후 적용 (리더)</span>}
      >
        {err && <div className="mb-2 text-xs" style={{ color: 'var(--red)' }}>채택 실패: {err}</div>}
        {!cands || cands.length === 0 ? (
          <Empty icon={Lightbulb}>
            아직 이관 후보가 없습니다. 판단 로그가 시그니처별로 반복·일관되면(빈도≥2, 일관성≥70%) 결정론적 패턴을 룰 초안으로 제안합니다.
          </Empty>
        ) : (
          <div className="space-y-3">
            {cands.map((c) => {
              const done = adopted.has(c.signature)
              return (
                <div key={c.signature} className="rounded-lg border border-[var(--border)] bg-[var(--panel-2)] p-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge text={c.verdict} color={c.verdict === 'block' ? 'var(--red)' : 'var(--green)'} />
                    <span className="font-mono text-xs">{c.method} {c.path}</span>
                    <span className="ml-auto flex items-center gap-2 text-xs text-[var(--muted)]">
                      <span>적중 <b className="text-[var(--text)]">{c.hits}</b></span>
                      <span>일관성 <b className="text-[var(--text)]">{Math.round(c.consistency * 100)}%</b></span>
                      <span>신뢰도 {Math.round(c.avg_confidence * 100)}%</span>
                      <span>예상절감 <b style={{ color: 'var(--green)' }}>-{c.est_savings}</b> 질의</span>
                    </span>
                  </div>
                  <div className="mt-2 rounded-md border border-[var(--border)] bg-[var(--panel)] p-2 font-mono text-[11px]">
                    <div className="mb-1 text-[var(--muted)]"># draft rule (YAML) — 검토 후 승인</div>
                    <div>name: {c.draft_rule.name}</div>
                    <div>action: <span style={{ color: c.verdict === 'block' ? 'var(--red)' : 'var(--green)' }}>{c.draft_rule.action}</span></div>
                    <div>methods: [{(c.draft_rule.methods ?? []).join(', ')}]</div>
                    <div>path_pattern: {c.draft_rule.path_pattern}</div>
                  </div>
                  {c.warning && (
                    <div className="mt-2 flex items-start gap-1.5 text-xs" style={{ color: 'var(--amber)' }}>
                      <TriangleAlert size={13} className="mt-0.5 shrink-0" /> {c.warning}
                    </div>
                  )}
                  <div className="mt-2.5 flex items-center gap-2">
                    {done ? (
                      <span className="inline-flex items-center gap-1.5 text-xs font-semibold" style={{ color: 'var(--green)' }}>
                        <Check size={14} /> 채택됨 — 활성 룰셋에 반영
                      </span>
                    ) : (
                      <button onClick={() => adopt(c)} disabled={busy === c.signature}
                              className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold disabled:opacity-50"
                              style={{ background: 'var(--accent)', color: 'var(--accent-fg)' }}>
                        <ShieldCheck size={13} /> {busy === c.signature ? '채택 중…' : '룰로 채택 (승인)'}
                      </button>
                    )}
                    <span className="text-[11px] text-[var(--muted)]">채택하면 이후 동일 요청은 LLM 없이 결정론적으로 판단됩니다.</span>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </Card>

      {/* 2) 활성 룰셋 */}
      <Card title={`활성 룰셋${activeRules ? ` (${activeRules.length})` : ''}`} icon={ShieldCheck}
            right={<span className="text-[11px] text-[var(--muted)]">위에서부터 우선 적용 (첫 매칭)</span>}>
        {!activeRules || activeRules.length === 0 ? (
          <Empty icon={ShieldCheck}>활성 룰이 없습니다.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm [font-variant-numeric:tabular-nums]">
              <thead>
                <tr className="eyebrow text-left">
                  <th className="pb-2 pr-3 font-semibold">#</th>
                  <th className="pb-2 pr-3 font-semibold">Name</th>
                  <th className="pb-2 pr-3 font-semibold">Action</th>
                  <th className="pb-2 pr-3 font-semibold">Methods</th>
                  <th className="pb-2 pr-3 font-semibold">Path pattern</th>
                  <th className="pb-2 pr-3 font-semibold">Reason</th>
                </tr>
              </thead>
              <tbody>
                {activeRules.map((r, i) => (
                  <tr key={r.name + i} className="border-t border-[var(--border)] align-top">
                    <td className="py-2 pr-3 text-xs text-[var(--muted)]">{i + 1}</td>
                    <td className="py-2 pr-3 font-mono text-xs">{r.name}</td>
                    <td className="py-2 pr-3">
                      <Badge text={r.action} color={r.action === 'block' ? 'var(--red)' : r.action === 'allow' ? 'var(--green)' : 'var(--blue)'} />
                    </td>
                    <td className="py-2 pr-3 font-mono text-xs text-[var(--muted)]">{(r.methods ?? []).join(', ') || '*'}</td>
                    <td className="py-2 pr-3 max-w-[300px] font-mono text-[11px] text-[var(--muted)]">{r.path_pattern || '*'}</td>
                    <td className="py-2 pr-3 text-xs text-[var(--muted)]">{r.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* 3) LLM 판단 로그 + 요약/필터 */}
      <DecisionLog data={data ?? []} />
    </div>
  )
}

function DecisionLog({ data }: { data: LLMDecision[] }) {
  const [filter, setFilter] = useState<'all' | 'allow' | 'block'>('all')
  const allow = data.filter((d) => d.verdict?.allow).length
  const block = data.length - allow
  const cacheHits = data.filter((d) => d.cached).length
  const hitRate = data.length ? Math.round((cacheHits / data.length) * 100) : 0
  const shown = filter === 'all' ? data : data.filter((d) => (filter === 'allow') === !!d.verdict?.allow)

  const chip = (active: boolean) =>
    `cursor-pointer rounded-full border px-2.5 py-0.5 text-xs ${active ? 'border-transparent font-semibold' : 'border-[var(--border)] text-[var(--muted)]'}`

  return (
    <Card title={`LLM Decision Log${data.length ? ` (${data.length})` : ''}`} icon={BrainCircuit}
          right={
            <span className="inline-flex items-center gap-1 text-[11px] text-[var(--muted)]" title="동일 시그니처 캐시 적중률 — 높을수록 룰 이관 효과 큼">
              <Zap size={12} style={{ color: 'var(--blue)' }} /> 캐시 적중 {cacheHits}/{data.length} ({hitRate}%)
            </span>
          }>
      <p className="mb-3 text-xs text-[var(--muted)]">
        프록시와 진단의 모든 LLM 판정을 기록합니다. 이 기록이 룰 추천의 근거가 됩니다.
      </p>
      {data.length === 0 ? (
        <Empty icon={BrainCircuit}>아직 LLM 판단 기록이 없습니다. LLM 스테이지가 애매한 요청을 판정하면 여기에 쌓입니다.</Empty>
      ) : (
        <>
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <span onClick={() => setFilter('all')} className={chip(filter === 'all')}
                  style={filter === 'all' ? { background: 'var(--panel-2)', color: 'var(--text)' } : undefined}>전체 {data.length}</span>
            <span onClick={() => setFilter('allow')} className={chip(filter === 'allow')}
                  style={filter === 'allow' ? { background: 'color-mix(in srgb, var(--green) 18%, transparent)', color: 'var(--green)' } : undefined}>allow {allow}</span>
            <span onClick={() => setFilter('block')} className={chip(filter === 'block')}
                  style={filter === 'block' ? { background: 'color-mix(in srgb, var(--red) 18%, transparent)', color: 'var(--red)' } : undefined}>block {block}</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm [font-variant-numeric:tabular-nums]">
              <thead>
                <tr className="eyebrow text-left">
                  <th className="pb-2 pr-3 font-semibold">#</th>
                  <th className="pb-2 pr-3 font-semibold">Request</th>
                  <th className="pb-2 pr-3 font-semibold">Verdict</th>
                  <th className="pb-2 pr-3 font-semibold">Conf.</th>
                  <th className="pb-2 pr-3 font-semibold">Reason</th>
                  <th className="pb-2 pr-3 font-semibold">Model</th>
                  <th className="pb-2 pr-3 font-semibold">Cache</th>
                </tr>
              </thead>
              <tbody>
                {[...shown].reverse().map((d) => (
                  <tr key={d.id} className="border-t border-[var(--border)] align-top">
                    <td className="py-2.5 pr-3 font-mono text-xs">{d.id}</td>
                    <td className="py-2.5 pr-3">
                      <div className="font-mono text-xs">{d.input?.method} {d.input?.path}</div>
                      <div className="font-mono text-[10px] text-[var(--muted)]">
                        [{(d.input?.param_keys ?? []).join(', ')}] {d.input?.content_type}
                      </div>
                    </td>
                    <td className="py-2.5 pr-3">
                      <Badge text={d.verdict?.allow ? 'allow' : 'block'} color={d.verdict?.allow ? 'var(--green)' : 'var(--red)'} />
                    </td>
                    <td className="py-2.5 pr-3 text-xs">{Math.round((d.verdict?.confidence ?? 0) * 100)}%</td>
                    <td className="py-2.5 pr-3 max-w-[240px] text-xs text-[var(--muted)]">{d.verdict?.reason}</td>
                    <td className="py-2.5 pr-3 text-xs text-[var(--muted)]">{d.verdict?.model || '—'}</td>
                    <td className="py-2.5 pr-3">{d.cached ? <Badge text="hit" color="var(--blue)" /> : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </Card>
  )
}
