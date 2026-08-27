import { useEffect, useRef, useState } from 'react'
import { Radar, Cpu, ShieldCheck, FlaskConical, Wrench, Inbox, Play, Pause, PlayCircle, Square, SlidersHorizontal, Sparkles, Terminal, ShieldAlert } from 'lucide-react'
import { usePoll, apiPost, useScanLog, type ScanRun, type DetectorInfo, type Stats, type Target, type LLMHealth, type Me } from '../api'
import { Card, Badge, Dot, Empty } from '../components/ui'
import { ScanRecommend } from '../components/ScanRecommend'
import { useT } from '../i18n'

interface Payloads { version: string; xss: string[]; sensitive_patterns: string[] }

// 스캔 상태별 색상.
const SCAN_STATUS: Record<string, string> = {
  '진행': 'var(--blue)', '일시정지': 'var(--amber)', '완료': 'var(--green)', '중단': 'var(--muted)',
}
const scanColor = (s: string) => SCAN_STATUS[s] ?? 'var(--muted)'

// 기본 선택에서 빼는 탐지기 — sqli-time은 요청마다 딜레이를 재는 시간 기반 블라인드라 스캔이 크게 느려짐.
// "전체선택" 버튼으로는 여전히 켤 수 있다.
const DEFAULT_EXCLUDED = new Set(['sqli-time'])

// LLMPanel — LLM 검토 체크박스 옆에 판단 스테이지 상태(#56)를 노출한다.
// 프로바이더·판단 불능 배지(읽기는 stats.llm_health)와 fail-open/closed 토글(리더만, POST
// /api/judge-on-error)을 한 줄에 모은다. Overview 는 배지만 보여주지만, 스캔 화면에서 LLM
// 검토를 켜는 사람은 "지금 판단이 살아있는가 + 죽으면 어떻게 되는가"를 같은 자리에서 봐야 한다.
function LLMPanel({ health, provider, canPolicy, onChanged }: {
  health?: LLMHealth; provider?: string; canPolicy: boolean; onChanged: () => void
}) {
  const t = useT()
  const [busy, setBusy] = useState(false)
  const policy = health?.policy ?? 'allow'

  async function setPolicy(p: string) {
    if (busy || p === policy) return
    setBusy(true)
    try { await apiPost('/api/judge-on-error', { policy: p }); onChanged() }
    catch (e) { alert(t('scan.llm.policyFail') + ': ' + e) } finally { setBusy(false) }
  }

  return (
    <div className="flex flex-wrap items-center gap-2 text-[11px]">
      <span className="inline-flex items-center gap-1 text-[var(--muted)]">
        <Cpu size={12} /> LLM · {provider ?? '—'}
      </span>
      {health?.degraded && (
        <span className="inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 font-semibold"
              style={{ background: 'color-mix(in srgb, var(--red) 18%, transparent)', color: 'var(--red)' }}
              title={health.reason}>
          <ShieldAlert size={11} /> {t('scan.llm.degraded', { count: String(health.count ?? 0) })}
        </span>
      )}
      {/* fail-open/closed — 판단 불능 시 통과(allow)/차단(block). 리더만 변경, 비리더는 현재값만 표시 */}
      <span className="inline-flex items-center gap-1 text-[var(--muted)]" title={t('scan.llm.policyTitle')}>
        {t('scan.llm.onError')}
        {canPolicy ? (
          <span className="inline-flex overflow-hidden rounded-md border border-[var(--border)]">
            {(['allow', 'block'] as const).map((p) => (
              <button key={p} type="button" disabled={busy} onClick={() => setPolicy(p)}
                      className="px-1.5 py-0.5 font-semibold disabled:opacity-50"
                      style={{ background: policy === p ? 'var(--panel-2)' : 'transparent',
                               color: policy === p ? (p === 'block' ? 'var(--red)' : 'var(--green)') : 'var(--muted)' }}>
                {p === 'block' ? t('scan.llm.policy.block') : t('scan.llm.policy.allow')}
              </button>
            ))}
          </span>
        ) : (
          <Badge text={policy === 'block' ? t('scan.llm.policy.block') : t('scan.llm.policy.allow')}
                 color={policy === 'block' ? 'var(--red)' : 'var(--green)'} />
        )}
      </span>
    </div>
  )
}

// ScanControl — 탐지기 선택 + 스캔 시작 (AppScan Test 대응, 진단 정책).
function ScanControl({ targetCount, dets, health, provider, canPolicy, onChanged }: {
  targetCount: number; dets: DetectorInfo[]; health?: LLMHealth; provider?: string; canPolicy: boolean; onChanged: () => void
}) {
  const t = useT()
  const [mode, setMode] = useState<'manual' | 'ai'>('manual')
  const [llm, setLlm] = useState(false)
  const [destructive, setDestructive] = useState(false)
  const [busy, setBusy] = useState(false)
  const [sel, setSel] = useState<Set<string>>(new Set())
  const [inited, setInited] = useState(false)
  const [aiPlan, setAiPlan] = useState<Record<string, string[]> | null>(null)

  // 탐지기 목록 로드되면 기본 선택 (1회, 수동 모드용) — DEFAULT_EXCLUDED 는 빼고 시작.
  useEffect(() => {
    if (!inited && dets.length > 0) {
      setSel(new Set(dets.filter((d) => !DEFAULT_EXCLUDED.has(d.id)).map((d) => d.id)))
      setInited(true)
    }
  }, [dets, inited])

  const toggle = (id: string) => setSel((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n })
  const allOn = () => setSel(new Set(dets.map((d) => d.id)))
  const allOff = () => setSel(new Set())

  async function start() {
    setBusy(true)
    try {
      if (mode === 'ai' && aiPlan) {
        // detectors 는 실제 쓰이는 모든 id 의 합집합이어야 한다(서버는 per_target을 이 안에서만 클립).
        const detectors = [...new Set(Object.values(aiPlan).flat())]
        await apiPost('/api/scan', { detectors, per_target: aiPlan, allow_destructive: destructive, llm_review: llm })
      } else {
        await apiPost('/api/scan', { detectors: [...sel], allow_destructive: destructive, llm_review: llm })
      }
    } catch (e) { alert(t('scan.startFail') + ': ' + e) } finally { setBusy(false) }
  }

  const nSel = sel.size
  const canStart = mode === 'manual' ? nSel > 0 : !!aiPlan

  return (
    <Card title={t('scan.start.title')} icon={Radar}
          right={<span className="text-[11px] text-[var(--muted)]">{t('scan.start.surfacePre')}<b className="text-[var(--text)]">{targetCount}</b>{t('scan.start.surfacePost')}</span>}>
      {/* 모드 탭: 수동 선택(전체 그리드) vs AI 추천(엔드포인트별) */}
      <div className="mb-3 flex items-center gap-1 text-xs">
        <button onClick={() => setMode('manual')}
                className="inline-flex items-center gap-1 rounded-md px-2 py-1 font-semibold"
                style={{ background: mode === 'manual' ? 'var(--panel-2)' : 'transparent', color: mode === 'manual' ? 'var(--text)' : 'var(--muted)' }}>
          <SlidersHorizontal size={12} /> {t('scan.mode.manual')}
        </button>
        <button onClick={() => setMode('ai')}
                className="inline-flex items-center gap-1 rounded-md px-2 py-1 font-semibold"
                style={{ background: mode === 'ai' ? 'var(--panel-2)' : 'transparent', color: mode === 'ai' ? 'var(--text)' : 'var(--muted)' }}>
          <Sparkles size={12} /> {t('scan.mode.ai')}
        </button>
      </div>

      {mode === 'manual' ? (
        <div className="mb-3">
          <div className="mb-1.5 flex items-center gap-2 text-xs">
            <span className="text-[var(--muted)]">{t('scan.start.detectorsPre')} <b className="text-[var(--text)]">{nSel}</b>/{dets.length} {t('scan.start.selected')}</span>
            <button onClick={allOn} className="text-[var(--muted)] underline">{t('scan.start.selectAll')}</button>
            <button onClick={allOff} className="text-[var(--muted)] underline">{t('scan.start.deselectAll')}</button>
          </div>
          <div className="grid grid-cols-2 gap-x-4 gap-y-1 sm:grid-cols-3">
            {dets.map((d) => (
              <label key={d.id} className="flex cursor-pointer items-center gap-1.5 text-xs"
                     title={d.tool && d.available === false ? t('scan.start.toolMissingTitle') : d.name}>
                <input type="checkbox" checked={sel.has(d.id)} onChange={() => toggle(d.id)} />
                <span className="font-mono">{d.id}</span>
                {d.destructive && <Badge text="D" color="var(--red)" />}
                {d.tool && d.available === false && <span className="text-[10px]" style={{ color: 'var(--amber)' }}>{t('scan.start.missing')}</span>}
              </label>
            ))}
          </div>
        </div>
      ) : (
        <div className="mb-3">
          <ScanRecommend dets={dets} allowDestructive={destructive} onPlanChange={setAiPlan} />
        </div>
      )}

      <div className="flex flex-wrap items-center gap-3 border-t border-[var(--border)] pt-3">
        <button onClick={start} disabled={busy || targetCount === 0 || !canStart}
                className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold disabled:opacity-50"
                style={{ background: 'var(--accent)', color: 'var(--accent-fg)' }}>
          <Play size={13} /> {busy ? t('scan.start.starting') : mode === 'manual' ? t('scan.start.scanWithN', { n: nSel }) : t('scan.start.scanAiPlan')}
        </button>
        <label className="flex cursor-pointer items-center gap-1.5 text-xs text-[var(--muted)]" title={t('scan.start.llmTitle')}>
          <input type="checkbox" checked={llm} onChange={(e) => setLlm(e.target.checked)} /> {t('scan.start.llmReview')}
        </label>
        <label className="flex cursor-pointer items-center gap-1.5 text-xs text-[var(--muted)]" title={t('scan.start.destructiveTitle')}>
          <input type="checkbox" checked={destructive} onChange={(e) => setDestructive(e.target.checked)} /> {t('scan.start.destructive')}
        </label>
        {targetCount === 0 && <span className="text-[11px]" style={{ color: 'var(--amber)' }}>{t('scan.start.noTargets')}</span>}
        {mode === 'manual' && nSel === 0 && targetCount > 0 && <span className="text-[11px]" style={{ color: 'var(--amber)' }}>{t('scan.start.noDetectors')}</span>}
        {mode === 'ai' && !aiPlan && targetCount > 0 && <span className="text-[11px]" style={{ color: 'var(--amber)' }}>{t('scan.ai.noPlan')}</span>}
      </div>

      {/* LLM 판단 스테이지 상태·정책 (이슈 #56·#62) — LLM 검토를 켤 때 판단 가용성을 같은 자리에서 본다 */}
      <div className="mt-2.5 border-t border-[var(--border)] pt-2.5">
        <LLMPanel health={health} provider={provider} canPolicy={canPolicy} onChanged={onChanged} />
      </div>
    </Card>
  )
}

// scanCtl — 실행 중 스캔 제어 (일시정지/재개/취소). 실패 메시지는 호출부에서 번역해 전달.
async function scanCtl(id: string, op: 'pause' | 'resume' | 'cancel', failMsg: string) {
  try { await apiPost(`/api/scanruns/${id}/${op}`, {}) }
  catch (e) { alert(failMsg + ': ' + e) }
}

function RunControls({ r }: { r: ScanRun }) {
  const t = useT()
  const [busy, setBusy] = useState(false)
  const act = async (op: 'pause' | 'resume' | 'cancel') => { setBusy(true); await scanCtl(r.id, op, t('scan.ctlFail')); setBusy(false) }
  const btn = 'inline-flex items-center gap-1 rounded-md border border-[var(--border)] px-1.5 py-0.5 text-[11px] disabled:opacity-50'
  if (r.status === '완료' || r.status === '중단') return <span className="text-[var(--muted)]">—</span>
  return (
    <div className="flex items-center gap-1">
      {r.status === '진행' && (
        <button className={btn} disabled={busy} onClick={() => act('pause')} title={t('scan.run.pauseTitle')}><Pause size={11} /> {t('scan.run.pause')}</button>
      )}
      {r.status === '일시정지' && (
        <button className={btn} disabled={busy} onClick={() => act('resume')} title={t('scan.run.resume')} style={{ color: 'var(--green)' }}><PlayCircle size={11} /> {t('scan.run.resume')}</button>
      )}
      <button className={btn} disabled={busy} onClick={() => { if (confirm(t('scan.run.cancelConfirm', { id: r.id }))) act('cancel') }} title={t('common.cancel')} style={{ color: 'var(--red)' }}>
        <Square size={11} /> {t('common.cancel')}
      </button>
    </div>
  )
}

// ScanLogPanel — 실행 중인 스캔의 요청 단위 실시간 로그 (SSE, 이슈 #59).
// 진행/일시정지 상태인 run 이 있으면 구독하고, 없으면 유휴 상태 안내만 보여준다.
function ScanLogPanel({ run }: { run?: ScanRun }) {
  const t = useT()
  const lines = useScanLog(run?.id)
  const boxRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const el = boxRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [lines])

  return (
    <Card title={t('scan.log.title')} icon={Terminal}
          right={run && <Dot text={run.status} color={scanColor(run.status)} />}>
      <div ref={boxRef} className="h-64 overflow-y-auto rounded-lg bg-[var(--panel-2)] p-2.5 font-mono text-[11px] leading-relaxed">
        {!run ? (
          <div className="text-[var(--muted)]">{t('scan.log.idle')}</div>
        ) : lines.length === 0 ? (
          <div className="text-[var(--muted)]">{t('scan.log.waiting')}</div>
        ) : (
          lines.map((l, i) => (
            <div key={i} className="whitespace-pre-wrap break-all"
                 style={{ color: l.message.includes('발견') ? 'var(--red)' : 'var(--text)' }}>
              <span className="text-[var(--muted)]">{new Date(l.time).toLocaleTimeString()}</span>{' '}
              {l.detector && <span style={{ color: 'var(--blue)' }}>[{l.detector}]</span>}{' '}
              {l.message}
            </div>
          ))
        )}
      </div>
    </Card>
  )
}

export function Scan() {
  const tr = useT() // 외부도구 map 의 t(tool) 파라미터와 섀도잉 회피
  const { data: runs } = usePoll<ScanRun[]>('/api/scanruns', 2000)
  const { data: dets } = usePoll<DetectorInfo[]>('/api/detectors', 8000)
  const { data: stats, refetch: refetchStats } = usePoll<Stats>('/api/stats', 5000)
  const { data: pl } = usePoll<Payloads>('/api/payloads', 10000)
  const { data: targets } = usePoll<Target[]>('/api/endpoints', 5000)
  const { data: me } = usePoll<Me>('/api/me', 30000)
  const canPolicy = !!me?.can?.includes('llm:policy')

  const tools = (dets ?? []).filter((d) => d.tool)
  // 실행 중인 스캔이 있으면 그걸, 없으면 가장 최근 스캔(완료됐어도)의 로그를 계속 볼 수 있게.
  // 서버는 완료된 실행의 로그도 재시작 전까지 메모리에 들고 있어 재생 가능하다 — 새 스캔을
  // 시작하기 전까진 직전 스캔 로그가 화면에서 사라지지 않는다.
  const runningRun = runs?.find((r) => r.status === '진행' || r.status === '일시정지')
  const latestRun = runs && runs.length > 0 ? runs[runs.length - 1] : undefined
  const logRun = runningRun ?? latestRun

  return (
    <div className="space-y-5">
      <ScanControl targetCount={targets?.length ?? 0} dets={dets ?? []}
                   health={stats?.llm_health} provider={stats?.llm_provider} canPolicy={canPolicy} onChanged={refetchStats} />
      <ScanLogPanel run={logRun} />
      {/* Scan Runs (FR-3.8) */}
      <Card title={`${tr('scan.runs.title')}${runs ? ` (${runs.length})` : ''}`} icon={Radar}>
        {!runs || runs.length === 0 ? (
          <Empty icon={Inbox}>{tr('overview.noScans')}</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm [font-variant-numeric:tabular-nums]">
              <thead>
                <tr className="eyebrow text-left">
                  <th className="pb-2 font-semibold">ID</th><th className="pb-2 font-semibold">{tr('scan.col.status')}</th>
                  <th className="pb-2 font-semibold">{tr('scan.col.detectors')}</th><th className="pb-2 font-semibold">{tr('scan.col.skipped')}</th>
                  <th className="pb-2 font-semibold">{tr('scan.col.progress')}</th><th className="pb-2 font-semibold">{tr('scan.col.findings')}</th>
                  <th className="pb-2 font-semibold">{tr('scan.col.safe')}</th><th className="pb-2 font-semibold">{tr('scan.col.control')}</th>
                </tr>
              </thead>
              <tbody>
                {[...runs].reverse().map((r) => (
                  <tr key={r.id} className="border-t border-[var(--border)] align-top">
                    <td className="py-2.5 font-mono text-xs">{r.id}</td>
                    <td className="py-2.5"><Dot text={r.status} color={scanColor(r.status)} /></td>
                    <td className="py-2.5 text-xs">{(r.detectors ?? []).join(', ') || '—'}</td>
                    <td className="py-2.5 text-xs text-[var(--muted)]">{(r.skipped ?? []).join(', ') || '—'}</td>
                    <td className="py-2.5">
                      <div className="flex items-center gap-2">
                        <div className="h-1.5 w-20 overflow-hidden rounded-full bg-[var(--panel-2)]">
                          <div className="h-full rounded-full" style={{ width: `${r.total ? (r.done / r.total) * 100 : 0}%`, background: scanColor(r.status) }} />
                        </div>
                        <span className="text-xs text-[var(--muted)]">{r.done}/{r.total}</span>
                      </div>
                    </td>
                    <td className="py-2.5 font-semibold">{r.findings}</td>
                    <td className="py-2.5">{r.safe_mode ? <Badge text="safe" color="var(--green)" /> : '—'}</td>
                    <td className="py-2.5"><RunControls r={r} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <div className="grid gap-5 lg:grid-cols-[2fr_1fr]">
        {/* Detector Catalog (FR-3.1 / FR-3.4) */}
        <Card title={`${tr('scan.detectors.title')}${dets ? ` (${dets.length})` : ''}`} icon={Cpu}>
          <div className="overflow-hidden rounded-lg border border-[var(--border)]">
            {(dets ?? []).map((d) => (
              <div key={d.id} className="flex items-center gap-3 border-t border-[var(--border)] first:border-t-0 px-3 py-2.5">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm">{d.id}</span>
                    {d.destructive && <Badge text="destructive" color="var(--red)" />}
                    {d.tool && <span className="inline-flex items-center gap-1 text-[11px] text-[var(--muted)]"><Wrench size={11} />{d.tool}</span>}
                  </div>
                  <div className="text-xs text-[var(--muted)]">{d.name}</div>
                </div>
                {d.tool ? (
                  <Dot text={d.available ? `${tr('scan.det.ready')}${d.version ? ' ' + d.version : ''}` : tr('scan.det.missing')}
                       color={d.available ? 'var(--green)' : 'var(--red)'} />
                ) : <Dot text={tr('scan.det.builtin')} color="var(--green)" />}
              </div>
            ))}
            {(!dets || dets.length === 0) && <Empty>{tr('scan.noDetectors')}</Empty>}
          </div>
        </Card>

        {/* 우측: 가드레일 + 페이로드 + 도구 */}
        <div className="space-y-5">
          <Card title={tr('scan.guardrails')} icon={ShieldCheck}>
            <Row k={tr('scan.gr.safeMode')} v={<Badge text={stats?.safe_mode ? 'On' : 'Off'} color={stats?.safe_mode ? 'var(--amber)' : 'var(--muted)'} dot />} />
            <Row k={tr('scan.gr.destructive')} v={<span className="text-xs text-[var(--muted)]">{tr('scan.gr.destructiveVal')}</span>} />
            <Row k={tr('scan.gr.rateLimit')} v={<span className="text-xs text-[var(--muted)]">{stats?.safe_mode ? '500ms' : '150ms'}/req</span>} />
            <Row k={tr('scan.gr.killSwitch')} v={<span className="text-xs text-[var(--green)]">{tr('scan.gr.available')}</span>} />
          </Card>

          <Card title={tr('scan.payloads')} icon={FlaskConical}>
            <div className="mb-2 flex items-center justify-between text-xs">
              <span className="text-[var(--muted)]">{tr('scan.pl.version')}</span>
              <span className="font-mono">{pl?.version ?? '—'}</span>
            </div>
            <div className="eyebrow mb-1">XSS ({pl?.xss?.length ?? 0})</div>
            <div className="mb-2 space-y-0.5">
              {(pl?.xss ?? []).map((x, i) => <div key={i} className="truncate font-mono text-[11px] text-[var(--muted)]">{x}</div>)}
            </div>
            <div className="eyebrow mb-1">{tr('scan.sensitivePatterns')} ({pl?.sensitive_patterns?.length ?? 0})</div>
            <div className="flex flex-wrap gap-1">
              {(pl?.sensitive_patterns ?? []).map((p) => <Badge key={p} text={p} color="var(--blue)" />)}
            </div>
          </Card>

          <Card title={tr('scan.externalTools')} icon={Wrench}>
            {tools.length === 0 ? <Empty>{tr('scan.noToolDetectors')}</Empty> : (
              <div className="space-y-2">
                {tools.map((t) => (
                  <div key={t.id} className="flex items-center justify-between text-sm">
                    <span className="font-mono text-xs">{t.tool}</span>
                    <Dot text={t.available ? (t.version || tr('scan.det.ready')) : tr('scan.det.missing')} color={t.available ? 'var(--green)' : 'var(--red)'} />
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      </div>
    </div>
  )
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between py-1 text-sm">
      <span className="text-[var(--muted)]">{k}</span>{v}
    </div>
  )
}
