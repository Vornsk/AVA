import { useEffect, useState } from 'react'
import { Radar, Cpu, ShieldCheck, FlaskConical, Wrench, Inbox, Play, Pause, PlayCircle, Square } from 'lucide-react'
import { usePoll, apiPost, type ScanRun, type DetectorInfo, type Stats, type Target } from '../api'
import { Card, Badge, Dot, Empty } from '../components/ui'

interface Payloads { version: string; xss: string[]; sensitive_patterns: string[] }

// 스캔 상태별 색상.
const SCAN_STATUS: Record<string, string> = {
  '진행': 'var(--blue)', '일시정지': 'var(--amber)', '완료': 'var(--green)', '중단': 'var(--muted)',
}
const scanColor = (s: string) => SCAN_STATUS[s] ?? 'var(--muted)'

// ScanControl — 탐지기 선택 + 스캔 시작 (AppScan Test 대응, 진단 정책).
function ScanControl({ targetCount, dets }: { targetCount: number; dets: DetectorInfo[] }) {
  const [llm, setLlm] = useState(false)
  const [destructive, setDestructive] = useState(false)
  const [busy, setBusy] = useState(false)
  const [sel, setSel] = useState<Set<string>>(new Set())
  const [inited, setInited] = useState(false)

  // 탐지기 목록 로드되면 기본 전체 선택 (1회).
  useEffect(() => {
    if (!inited && dets.length > 0) { setSel(new Set(dets.map((d) => d.id))); setInited(true) }
  }, [dets, inited])

  const toggle = (id: string) => setSel((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n })
  const allOn = () => setSel(new Set(dets.map((d) => d.id)))
  const allOff = () => setSel(new Set())

  async function start() {
    setBusy(true)
    try { await apiPost('/api/scan', { detectors: [...sel], allow_destructive: destructive, llm_review: llm }) }
    catch (e) { alert('스캔 시작 실패: ' + e) } finally { setBusy(false) }
  }

  const nSel = sel.size

  return (
    <Card title="스캔 시작" icon={Radar}
          right={<span className="text-[11px] text-[var(--muted)]">공격면 <b className="text-[var(--text)]">{targetCount}</b>개 대상</span>}>
      {/* 탐지기 선택 */}
      <div className="mb-3">
        <div className="mb-1.5 flex items-center gap-2 text-xs">
          <span className="text-[var(--muted)]">탐지기 <b className="text-[var(--text)]">{nSel}</b>/{dets.length} 선택</span>
          <button onClick={allOn} className="text-[var(--muted)] underline">전체선택</button>
          <button onClick={allOff} className="text-[var(--muted)] underline">전체해제</button>
        </div>
        <div className="grid grid-cols-2 gap-x-4 gap-y-1 sm:grid-cols-3">
          {dets.map((d) => (
            <label key={d.id} className="flex cursor-pointer items-center gap-1.5 text-xs"
                   title={d.tool && d.available === false ? '외부 도구 미설치 — 선택해도 건너뜀' : d.name}>
              <input type="checkbox" checked={sel.has(d.id)} onChange={() => toggle(d.id)} />
              <span className="font-mono">{d.id}</span>
              {d.destructive && <Badge text="D" color="var(--red)" />}
              {d.tool && d.available === false && <span className="text-[10px]" style={{ color: 'var(--amber)' }}>미설치</span>}
            </label>
          ))}
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-3 border-t border-[var(--border)] pt-3">
        <button onClick={start} disabled={busy || targetCount === 0 || nSel === 0}
                className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold disabled:opacity-50"
                style={{ background: 'var(--accent)', color: 'var(--accent-fg)' }}>
          <Play size={13} /> {busy ? '시작 중…' : `선택 ${nSel}개로 스캔`}
        </button>
        <label className="flex cursor-pointer items-center gap-1.5 text-xs text-[var(--muted)]" title="각 finding을 LLM이 오탐 검토(주석). 판정은 상태를 안 바꿈(HITL)">
          <input type="checkbox" checked={llm} onChange={(e) => setLlm(e.target.checked)} /> LLM 오탐 검토
        </label>
        <label className="flex cursor-pointer items-center gap-1.5 text-xs text-[var(--muted)]" title="파괴적 탐지기(file-upload 등) 포함 — 대상에 파일 생성 등 부작용 가능">
          <input type="checkbox" checked={destructive} onChange={(e) => setDestructive(e.target.checked)} /> 파괴적 포함
        </label>
        {targetCount === 0 && <span className="text-[11px]" style={{ color: 'var(--amber)' }}>먼저 정찰에서 크롤하거나 프록시로 트래픽을 흘리세요</span>}
        {nSel === 0 && targetCount > 0 && <span className="text-[11px]" style={{ color: 'var(--amber)' }}>탐지기를 1개 이상 선택하세요</span>}
      </div>
    </Card>
  )
}

// scanCtl — 실행 중 스캔 제어 (일시정지/재개/취소).
async function scanCtl(id: string, op: 'pause' | 'resume' | 'cancel') {
  try { await apiPost(`/api/scanruns/${id}/${op}`, {}) }
  catch (e) { alert('제어 실패: ' + e) }
}

function RunControls({ r }: { r: ScanRun }) {
  const [busy, setBusy] = useState(false)
  const act = async (op: 'pause' | 'resume' | 'cancel') => { setBusy(true); await scanCtl(r.id, op); setBusy(false) }
  const btn = 'inline-flex items-center gap-1 rounded-md border border-[var(--border)] px-1.5 py-0.5 text-[11px] disabled:opacity-50'
  if (r.status === '완료' || r.status === '중단') return <span className="text-[var(--muted)]">—</span>
  return (
    <div className="flex items-center gap-1">
      {r.status === '진행' && (
        <button className={btn} disabled={busy} onClick={() => act('pause')} title="일시정지"><Pause size={11} /> 정지</button>
      )}
      {r.status === '일시정지' && (
        <button className={btn} disabled={busy} onClick={() => act('resume')} title="재개" style={{ color: 'var(--green)' }}><PlayCircle size={11} /> 재개</button>
      )}
      <button className={btn} disabled={busy} onClick={() => { if (confirm(`${r.id} 스캔을 취소할까요?`)) act('cancel') }} title="취소" style={{ color: 'var(--red)' }}>
        <Square size={11} /> 취소
      </button>
    </div>
  )
}

export function Scan() {
  const { data: runs } = usePoll<ScanRun[]>('/api/scanruns', 2000)
  const { data: dets } = usePoll<DetectorInfo[]>('/api/detectors', 8000)
  const { data: stats } = usePoll<Stats>('/api/stats', 5000)
  const { data: pl } = usePoll<Payloads>('/api/payloads', 10000)
  const { data: targets } = usePoll<Target[]>('/api/endpoints', 5000)

  const tools = (dets ?? []).filter((d) => d.tool)

  return (
    <div className="space-y-5">
      <ScanControl targetCount={targets?.length ?? 0} dets={dets ?? []} />
      {/* Scan Runs (FR-3.8) */}
      <Card title={`Scan Runs${runs ? ` (${runs.length})` : ''}`} icon={Radar}>
        {!runs || runs.length === 0 ? (
          <Empty icon={Inbox}>아직 실행된 스캔이 없습니다.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm [font-variant-numeric:tabular-nums]">
              <thead>
                <tr className="eyebrow text-left">
                  <th className="pb-2 font-semibold">ID</th><th className="pb-2 font-semibold">Status</th>
                  <th className="pb-2 font-semibold">Detectors</th><th className="pb-2 font-semibold">Skipped</th>
                  <th className="pb-2 font-semibold">Progress</th><th className="pb-2 font-semibold">Findings</th>
                  <th className="pb-2 font-semibold">Safe</th><th className="pb-2 font-semibold">제어</th>
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
        <Card title={`Detectors${dets ? ` (${dets.length})` : ''}`} icon={Cpu}>
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
                  <Dot text={d.available ? `ready${d.version ? ' ' + d.version : ''}` : 'missing'}
                       color={d.available ? 'var(--green)' : 'var(--red)'} />
                ) : <Dot text="built-in" color="var(--green)" />}
              </div>
            ))}
            {(!dets || dets.length === 0) && <Empty>탐지기 없음</Empty>}
          </div>
        </Card>

        {/* 우측: 가드레일 + 페이로드 + 도구 */}
        <div className="space-y-5">
          <Card title="가드레일" icon={ShieldCheck}>
            <Row k="Safe mode" v={<Badge text={stats?.safe_mode ? 'On' : 'Off'} color={stats?.safe_mode ? 'var(--amber)' : 'var(--muted)'} dot />} />
            <Row k="Destructive" v={<span className="text-xs text-[var(--muted)]">opt-in only</span>} />
            <Row k="Rate limit" v={<span className="text-xs text-[var(--muted)]">{stats?.safe_mode ? '500ms' : '150ms'}/req</span>} />
            <Row k="Kill switch" v={<span className="text-xs text-[var(--green)]">available</span>} />
          </Card>

          <Card title="페이로드" icon={FlaskConical}>
            <div className="mb-2 flex items-center justify-between text-xs">
              <span className="text-[var(--muted)]">version</span>
              <span className="font-mono">{pl?.version ?? '—'}</span>
            </div>
            <div className="eyebrow mb-1">XSS ({pl?.xss?.length ?? 0})</div>
            <div className="mb-2 space-y-0.5">
              {(pl?.xss ?? []).map((x, i) => <div key={i} className="truncate font-mono text-[11px] text-[var(--muted)]">{x}</div>)}
            </div>
            <div className="eyebrow mb-1">한국형 민감패턴 ({pl?.sensitive_patterns?.length ?? 0})</div>
            <div className="flex flex-wrap gap-1">
              {(pl?.sensitive_patterns ?? []).map((p) => <Badge key={p} text={p} color="var(--blue)" />)}
            </div>
          </Card>

          <Card title="외부 도구" icon={Wrench}>
            {tools.length === 0 ? <Empty>도구 기반 탐지기 없음</Empty> : (
              <div className="space-y-2">
                {tools.map((t) => (
                  <div key={t.id} className="flex items-center justify-between text-sm">
                    <span className="font-mono text-xs">{t.tool}</span>
                    <Dot text={t.available ? (t.version || 'ready') : 'not found'} color={t.available ? 'var(--green)' : 'var(--red)'} />
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
