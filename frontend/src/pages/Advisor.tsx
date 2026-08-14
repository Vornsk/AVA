import { useState } from 'react'
import { BrainCircuit, Lightbulb, TriangleAlert, ShieldCheck, Check, Zap } from 'lucide-react'
import { usePoll, apiPost, type LLMDecision, type RuleCandidate, type Rule } from '../api'
import { Card, Badge, Empty } from '../components/ui'
import { useT } from '../i18n'

export function Advisor() {
  const t = useT()
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
        title={`${t('advisor.candidatesTitle')}${cands ? ` — ${cands.length}` : ''}`}
        icon={Lightbulb}
        right={<span className="text-[11px] text-[var(--muted)]">{t('advisor.proposalNote')}</span>}
      >
        {err && <div className="mb-2 text-xs" style={{ color: 'var(--red)' }}>{t('advisor.adoptFailed')}: {err}</div>}
        {!cands || cands.length === 0 ? (
          <Empty icon={Lightbulb}>
            {t('advisor.noCandidates')}
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
                      <span>{t('advisor.hits')} <b className="text-[var(--text)]">{c.hits}</b></span>
                      <span>{t('advisor.consistency')} <b className="text-[var(--text)]">{Math.round(c.consistency * 100)}%</b></span>
                      <span>{t('advisor.confidence')} {Math.round(c.avg_confidence * 100)}%</span>
                      <span>{t('advisor.estSavings')} <b style={{ color: 'var(--green)' }}>-{c.est_savings}</b> {t('advisor.queries')}</span>
                    </span>
                  </div>
                  <div className="mt-2 rounded-md border border-[var(--border)] bg-[var(--panel)] p-2 font-mono text-[11px]">
                    <div className="mb-1 text-[var(--muted)]">{t('advisor.draftRuleComment')}</div>
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
                        <Check size={14} /> {t('advisor.adopted')}
                      </span>
                    ) : (
                      <button onClick={() => adopt(c)} disabled={busy === c.signature}
                              className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold disabled:opacity-50"
                              style={{ background: 'var(--accent)', color: 'var(--accent-fg)' }}>
                        <ShieldCheck size={13} /> {busy === c.signature ? t('advisor.adopting') : t('advisor.adoptButton')}
                      </button>
                    )}
                    <span className="text-[11px] text-[var(--muted)]">{t('advisor.adoptHint')}</span>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </Card>

      {/* 2) 활성 룰셋 */}
      <Card title={`${t('advisor.activeRuleset')}${activeRules ? ` (${activeRules.length})` : ''}`} icon={ShieldCheck}
            right={<span className="text-[11px] text-[var(--muted)]">{t('advisor.rulesetNote')}</span>}>
        {!activeRules || activeRules.length === 0 ? (
          <Empty icon={ShieldCheck}>{t('advisor.noActiveRules')}</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm [font-variant-numeric:tabular-nums]">
              <thead>
                <tr className="eyebrow text-left">
                  <th className="pb-2 pr-3 font-semibold">#</th>
                  <th className="pb-2 pr-3 font-semibold">{t('advisor.colName')}</th>
                  <th className="pb-2 pr-3 font-semibold">{t('advisor.colAction')}</th>
                  <th className="pb-2 pr-3 font-semibold">{t('advisor.colMethods')}</th>
                  <th className="pb-2 pr-3 font-semibold">{t('advisor.colPathPattern')}</th>
                  <th className="pb-2 pr-3 font-semibold">{t('advisor.colReason')}</th>
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
  const t = useT()
  const [filter, setFilter] = useState<'all' | 'allow' | 'block'>('all')
  const allow = data.filter((d) => d.verdict?.allow).length
  const block = data.length - allow
  const cacheHits = data.filter((d) => d.cached).length
  const hitRate = data.length ? Math.round((cacheHits / data.length) * 100) : 0
  const shown = filter === 'all' ? data : data.filter((d) => (filter === 'allow') === !!d.verdict?.allow)

  const chip = (active: boolean) =>
    `cursor-pointer rounded-full border px-2.5 py-0.5 text-xs ${active ? 'border-transparent font-semibold' : 'border-[var(--border)] text-[var(--muted)]'}`

  return (
    <Card title={`${t('advisor.decisionLog')}${data.length ? ` (${data.length})` : ''}`} icon={BrainCircuit}
          right={
            <span className="inline-flex items-center gap-1 text-[11px] text-[var(--muted)]" title={t('advisor.cacheHitTooltip')}>
              <Zap size={12} style={{ color: 'var(--blue)' }} /> {t('advisor.cacheHit')} {cacheHits}/{data.length} ({hitRate}%)
            </span>
          }>
      <p className="mb-3 text-xs text-[var(--muted)]">
        {t('advisor.logIntro')}
      </p>
      {data.length === 0 ? (
        <Empty icon={BrainCircuit}>{t('advisor.noDecisions')}</Empty>
      ) : (
        <>
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <span onClick={() => setFilter('all')} className={chip(filter === 'all')}
                  style={filter === 'all' ? { background: 'var(--panel-2)', color: 'var(--text)' } : undefined}>{t('advisor.all')} {data.length}</span>
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
                  <th className="pb-2 pr-3 font-semibold">{t('advisor.colRequest')}</th>
                  <th className="pb-2 pr-3 font-semibold">{t('advisor.colVerdict')}</th>
                  <th className="pb-2 pr-3 font-semibold">{t('advisor.colConf')}</th>
                  <th className="pb-2 pr-3 font-semibold">{t('advisor.colReason')}</th>
                  <th className="pb-2 pr-3 font-semibold">{t('advisor.colModel')}</th>
                  <th className="pb-2 pr-3 font-semibold">{t('advisor.colCache')}</th>
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
                    <td className="py-2.5 pr-3">{d.cached ? <Badge text={t('advisor.cacheHitBadge')} color="var(--blue)" /> : '—'}</td>
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
