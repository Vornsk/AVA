import { useEffect, useState } from 'react'
import { BrainCircuit, Lightbulb, TriangleAlert, ShieldCheck, Check, Zap, SlidersHorizontal } from 'lucide-react'
import { usePoll, apiPost, type LLMDecision, type RuleCandidate, type Rule, type Me, type JudgePromptView } from '../api'
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

      {/* 3) 판단 프롬프트 정책 (이슈 #53) */}
      <JudgePromptCard />

      {/* 4) LLM 판단 로그 + 요약/필터 */}
      <DecisionLog data={data ?? []} />
    </div>
  )
}

// JudgePromptCard — 판단 프롬프트 정책 선택 (이슈 #53).
// 프리셋 3종 또는 커스텀. 변경은 리더 전용(llm:policy)이며 활성 프로젝트에 저장된다.
function JudgePromptCard() {
  const t = useT()
  const { data: me } = usePoll<Me>('/api/me', 30000)
  const { data: view } = usePoll<JudgePromptView>('/api/judge-prompt', 10000)
  const canEdit = !!me?.can?.includes('llm:policy')

  const [preset, setPreset] = useState<string | null>(null)
  const [custom, setCustom] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [saved, setSaved] = useState(false)

  // 서버 값으로 1회 초기화 (사용자가 편집 중이면 덮어쓰지 않는다)
  useEffect(() => {
    if (!view) return
    setPreset((p) => (p === null ? view.project_preset ?? view.active.id : p))
    setCustom((c) => (c === null ? view.project_custom ?? '' : c))
  }, [view])

  if (!view) return null
  const usingCustom = !!custom?.trim()
  const effective = usingCustom ? 'custom' : preset || view.base.id
  const preview = usingCustom ? custom! : view.presets.find((p) => p.id === effective)?.system ?? view.base.system

  async function save() {
    setBusy(true); setErr(''); setSaved(false)
    try {
      await apiPost('/api/judge-prompt', { preset: usingCustom ? '' : preset, custom: custom ?? '' })
      setSaved(true)
    } catch (e) { setErr(String(e)) } finally { setBusy(false) }
  }

  return (
    <Card title={t('advisor.promptTitle')} icon={SlidersHorizontal}
          right={<span className="font-mono text-[11px] text-[var(--muted)]">{t('advisor.promptActive')} {view.active.id} · {view.active.hash}</span>}>
      <p className="mb-3 text-xs text-[var(--muted)]">{t('advisor.promptIntro')}</p>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        {view.presets.map((p) => (
          <span key={p.id}
                onClick={() => { if (canEdit) { setPreset(p.id); setCustom(''); setSaved(false) } }}
                className={`rounded-full border px-2.5 py-0.5 text-xs ${canEdit ? 'cursor-pointer' : ''} ${effective === p.id ? 'border-transparent font-semibold' : 'border-[var(--border)] text-[var(--muted)]'}`}
                style={effective === p.id ? { background: 'var(--panel-2)', color: 'var(--text)' } : undefined}>
            {p.id}
          </span>
        ))}
        {usingCustom && <Badge text="custom" color="var(--blue)" />}
      </div>
      <textarea
        className="w-full rounded-md border border-[var(--border)] bg-[var(--panel-2)] p-2 font-mono text-[11px]"
        rows={4} disabled={!canEdit} maxLength={view.max_custom_len}
        placeholder={t('advisor.promptCustomPlaceholder')}
        value={custom ?? ''} onChange={(e) => { setCustom(e.target.value); setSaved(false) }} />
      <div className="mt-2 rounded-md border border-[var(--border)] bg-[var(--panel)] p-2 font-mono text-[11px] text-[var(--muted)]">
        {preview}
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        {canEdit ? (
          <button onClick={save} disabled={busy}
                  className="rounded-md border border-[var(--border)] bg-[var(--panel-2)] px-3 py-1 text-xs disabled:opacity-50">
            {busy ? t('advisor.promptSaving') : t('advisor.promptSave')}
          </button>
        ) : (
          <span className="text-[11px] text-[var(--muted)]">{t('advisor.promptLeaderOnly')}</span>
        )}
        {saved && <span className="inline-flex items-center gap-1 text-[11px]" style={{ color: 'var(--green)' }}><Check size={12} /> {t('advisor.promptSaved')}</span>}
        {err && <span className="text-[11px]" style={{ color: 'var(--red)' }}>{err}</span>}
        <span className="ml-auto text-[11px] text-[var(--muted)]">{t('advisor.promptCacheNote')}</span>
      </div>
    </Card>
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
                  <th className="pb-2 pr-3 font-semibold">{t('advisor.colPrompt')}</th>
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
                    <td className="py-2.5 pr-3 font-mono text-[11px] text-[var(--muted)]" title={d.verdict?.prompt_hash ?? ''}>
                      {d.verdict?.prompt || '—'}
                    </td>
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
