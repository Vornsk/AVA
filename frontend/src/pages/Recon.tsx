import { useState } from 'react'
import { Network, Filter, Globe, KeyRound, ShieldCheck, Radar, Play, Search, ChevronRight, Clock, Server, Copy, Check, Power, Crosshair, Activity, ScanLine, ArrowRight, ClipboardCheck } from 'lucide-react'
import { usePoll, apiPost, type Target, type Rule, type Stats, type AuthSummary, type CrawlResult, type LoginSeqInfo, type ProxyStatus, type Me, type ReconRegmap } from '../api'
import { Card, Badge, Dot, Empty, Tooltip, InfoTip } from '../components/ui'
import { useT } from '../i18n'

// CopyLine — 복사 가능한 명령/코드 한 줄.
function CopyLine({ text }: { text: string }) {
  const t = useT()
  const [copied, setCopied] = useState(false)
  return (
    <div className="flex items-center gap-2 rounded-lg border border-[var(--border)] bg-[var(--panel-2)] px-2 py-1.5">
      <code className="flex-1 overflow-x-auto whitespace-nowrap font-mono text-[11px]">{text}</code>
      <button type="button" aria-label={t('recon.copy')}
              onClick={() => { navigator.clipboard?.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1200) }}
              className="shrink-0 text-[var(--muted)] hover:text-[var(--text)]">
        {copied ? <Check size={13} className="text-[var(--green)]" /> : <Copy size={13} />}
      </button>
    </div>
  )
}

// ProxyTool — 정찰 페이지 프록시 도구(이슈 #9): 공용 :8080 상태·캡처 제어·설정 안내·트래픽 유도.
// 신규 백엔드 없이 기존 API만 사용 (상태 GET /api/proxy, 토글 POST /api/proxy/capture — #5).
function ProxyTool({ stats }: { stats: Stats | null }) {
  const t = useT()
  const { data: proxy } = usePoll<ProxyStatus>('/api/proxy', 4000)
  const { data: me } = usePoll<Me>('/api/me', 30000)
  const canControl = !!me?.can?.includes('proxy:control')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  async function toggle() {
    if (!proxy) return
    setBusy(true); setErr('')
    try { await apiPost('/api/proxy/capture', { on: !proxy.capturing }) }
    catch (e) { setErr(String(e)) } finally { setBusy(false) }
  }

  const listen = proxy?.listen || '127.0.0.1:8080'
  const capturing = proxy?.capturing ?? false

  return (
    <Card title={t('recon.proxy.title')} icon={Server}
          right={<Dot text={capturing ? t('recon.proxy.capturingOn') : t('recon.proxy.capturingOff')} color={capturing ? 'var(--green)' : 'var(--muted)'} />}>
      {/* 상태 */}
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Stat label={t('recon.proxy.listen')} value={listen} mono />
        <Stat label={t('recon.proxy.capturedTotal')} value={String(proxy?.captured_requests ?? 0)} />
        <Stat label={t('recon.proxy.endpoints')} value={`${proxy?.endpoints ?? 0} / ${proxy?.hosts ?? 0}host`} />
        <Stat label={t('recon.proxy.scope')} value={`${proxy?.scope_hosts ?? 0}host`} />
      </div>

      {/* 캡처 제어 */}
      <div className="mt-3 flex items-center gap-2">
        <button type="button" onClick={toggle} disabled={!canControl || busy || !proxy}
                className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold disabled:opacity-50"
                style={{ background: capturing ? 'transparent' : 'var(--accent)', color: capturing ? 'var(--text)' : 'var(--accent-fg)', border: capturing ? '1px solid var(--border)' : 'none' }}>
          <Power size={13} /> {busy ? t('recon.proxy.applying') : capturing ? t('recon.proxy.captureOff') : t('recon.proxy.captureOn')}
        </button>
        {!canControl && <span className="text-[11px] text-[var(--muted)]">{t('recon.proxy.needLeader')}</span>}
        {err && <span className="text-[11px]" style={{ color: 'var(--red)' }}>{t('recon.proxy.failPrefix')}: {err}</span>}
      </div>
      {!capturing && (
        <p className="mt-1.5 text-[11px] text-[var(--amber)]">{t('recon.proxy.captureOffWarn')}</p>
      )}

      {/* 설정 안내 */}
      <div className="mt-3 border-t border-[var(--border)] pt-2.5">
        <div className="mb-1.5 flex items-center justify-between text-xs">
          <span className="text-[var(--muted)]">{t('recon.proxy.caStatus')}</span>
          <Dot text={stats?.ca_trusted ? t('recon.proxy.trusted') : t('recon.proxy.untrusted')} color={stats?.ca_trusted ? 'var(--green)' : 'var(--amber)'} />
        </div>
        {!stats?.ca_trusted && (
          <div className="space-y-1">
            <p className="text-[11px] text-[var(--muted)]">{t('recon.proxy.caInstall')}</p>
            <CopyLine text="proxy-poc.exe -cert-install" />
          </div>
        )}
      </div>

      {/* 트래픽 유도 */}
      <div className="mt-3 border-t border-[var(--border)] pt-2.5">
        <div className="eyebrow mb-1.5">{t('recon.proxy.driveTraffic')}</div>
        <p className="mb-1.5 text-[11px] text-[var(--muted)]">
          {t('recon.proxy.driveDesc1')}<code className="font-mono">{listen}</code>{t('recon.proxy.driveDesc2')}
        </p>
        <CopyLine text={`curl.exe -sk -x http://${listen} "${t('recon.proxy.inScopeUrl')}"`} />
      </div>
    </Card>
  )
}

function Stat({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-lg border border-[var(--border)] bg-[var(--panel-2)] px-2.5 py-1.5">
      <div className="text-[10px] text-[var(--muted)]">{label}</div>
      <div className={`truncate text-sm font-semibold ${mono ? 'font-mono text-xs' : ''}`}>{value}</div>
    </div>
  )
}

// fmtTime — RFC3339 시각을 로캘 표기로. 값 없으면 —.
function fmtTime(s?: string) {
  if (!s) return '—'
  const d = new Date(s)
  return isNaN(d.getTime()) ? s : d.toLocaleString()
}

// CrawlExplore — 자동 공격면 탐색(AppScan Explore 대응). 시작 URL에서 링크·폼을 따라 자동 크롤.
function CrawlExplore() {
  const t = useT()
  const [seed, setSeed] = useState('')
  const [busy, setBusy] = useState(false)
  const [headless, setHeadless] = useState(false)
  const [paramMine, setParamMine] = useState(false) // 파라미터 마이닝 옵트인 (#40)
  const { data: runs } = usePoll<CrawlResult[]>('/api/crawl', 2000)
  const { data: modes } = usePoll<{ headless_available: boolean }>('/api/crawl-modes', 30000)
  const hlOK = modes?.headless_available === true
  const latest = runs && runs.length ? runs[runs.length - 1] : null
  const running = latest?.status === '진행'

  async function start() {
    if (!seed.trim()) return
    setBusy(true)
    try { await apiPost('/api/crawl', { seed: seed.trim(), mode: headless ? 'headless' : 'static', param_mine: paramMine }) }
    catch (e) { alert(t('recon.crawl.startFail') + ': ' + e) } finally { setBusy(false) }
  }

  return (
    <Card title={t('recon.crawl.title')} icon={Radar}
          right={<span className="hidden text-[11px] text-[var(--muted)] md:inline">{t('recon.crawl.subtitle')}</span>}>
      <div className="flex gap-2">
        <input value={seed} onChange={(e) => setSeed(e.target.value)}
               onKeyDown={(e) => e.key === 'Enter' && start()}
               placeholder={t('recon.crawl.seedPlaceholder')}
               className="flex-1 rounded-lg border border-[var(--border)] bg-[var(--panel-2)] px-3 py-1.5 font-mono text-xs" />
        <button onClick={start} disabled={busy || running || !seed.trim()}
                title={!seed.trim() ? t('recon.crawl.needSeed') : undefined}
                className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold disabled:cursor-not-allowed disabled:opacity-50"
                style={{ background: 'var(--accent)', color: 'var(--accent-fg)' }}>
          <Play size={13} /> {busy ? t('recon.crawl.starting') : running ? t('recon.crawl.running') : t('recon.crawl.start')}
        </button>
      </div>
      <label className={`mt-2 flex items-center gap-1.5 text-xs ${hlOK ? 'cursor-pointer text-[var(--muted)]' : 'text-[var(--muted)] opacity-50'}`}
             title={hlOK ? t('recon.crawl.hlTitleOn') : t('recon.crawl.hlTitleOff')}>
        <input type="checkbox" checked={headless && hlOK} disabled={!hlOK} onChange={(e) => setHeadless(e.target.checked)} />
        {t('recon.crawl.headless')} {hlOK ? <span style={{ color: 'var(--green)' }}>{t('recon.crawl.available')}</span> : <span>{t('recon.crawl.noChrome')}</span>}
      </label>
      <label className="mt-1.5 flex cursor-pointer items-center gap-1.5 text-xs text-[var(--muted)]"
             title={t('recon.crawl.paramMineTitle')}>
        <input type="checkbox" checked={paramMine} onChange={(e) => setParamMine(e.target.checked)} />
        {t('recon.crawl.paramMine')} <span style={{ color: 'var(--amber)' }}>{t('recon.crawl.optIn')}</span>
      </label>
      {latest && (
        <div className="mt-2.5 flex flex-wrap items-center gap-3 text-xs">
          <Dot text={latest.status} color={latest.status === '진행' ? 'var(--amber)' : latest.status === '완료' ? 'var(--green)' : 'var(--muted)'} />
          {latest.mode === 'headless' && <Badge text="headless" color="var(--blue)" />}
          <span className="text-[var(--muted)]"><b className="text-[var(--text)]">{latest.pages}</b> {t('recon.crawl.pages')}</span>
          <span className="text-[var(--muted)]">{t('recon.crawl.found')} <b className="text-[var(--text)]">{latest.found}</b></span>
          {latest.js > 0 && <span className="text-[var(--muted)]">JS <b className="text-[var(--text)]">{latest.js}</b></span>}
          {!!latest.mined && latest.mined > 0 && <span style={{ color: 'var(--amber)' }}>{t('recon.crawl.mined')} <b>{latest.mined}</b></span>}
          {!!latest.labeled && latest.labeled > 0 && <span className="text-[var(--muted)]">{t('recon.crawl.labeled')} <b className="text-[var(--text)]">{latest.labeled}</b></span>}
          <span className="text-[var(--muted)]">{t('recon.crawl.queued')} {latest.queued}</span>
          {latest.errors > 0 && <span style={{ color: 'var(--amber)' }}>{t('recon.crawl.errors')} {latest.errors}</span>}
          <span className="font-mono text-[10px] text-[var(--muted)]">{latest.seed}</span>
        </div>
      )}
    </Card>
  )
}

// EndpointTree — 캡처된 공격면 조회 (이슈 #7): 검색·메서드·인증·판정 필터 + 행 클릭 상세 드릴다운.
// SOURCE_META — 출처 신뢰도 등급별 라벨·색 (#28). 위에서부터 신뢰도 높음.
const SOURCE_META: Record<string, { label: string; color: string; key: string }> = {
  'spec': { label: 'spec', color: 'var(--green)', key: 'spec' },
  'traffic': { label: 'traffic', color: 'var(--accent)', key: 'traffic' },
  'headless-xhr': { label: 'xhr', color: 'var(--blue)', key: 'xhr' },
  'discover': { label: 'discover', color: '#a78bfa', key: 'discover' },
  'crawl-link': { label: 'crawl', color: 'var(--muted)', key: 'crawl' },
  'static-regex': { label: 'regex', color: 'var(--muted)', key: 'regex' },
}
// LABEL_META — 의미 라벨 색 (#41·#43). 라벨마다 고유색이다 — 민감 라벨을 전부 red 로 두면
// "결제"와 "관리자"를 색으로 구분할 수 없어 배지가 경고등 역할만 하고 정보를 못 준다.
// 키 순서 = 민감도 순. 행에서 접힐 때 덜 중요한 것부터 접힌다.
const LABEL_META: Record<string, string> = {
  payment: 'var(--red)',
  admin: '#f97316',
  pii: '#d946ef',
  auth: 'var(--amber)',
  upload: '#14b8a6',
  search: 'var(--blue)',
}
const LABEL_ORDER = Object.keys(LABEL_META)
const MAX_ROW_LABELS = 3 // 행 배지 상한. 넘으면 +N 으로 접어 경로가 밀리는 것을 막는다 (#43 합의 ①).

// 행 배지에는 의미 라벨만 보인다(구조적 api·static·other 는 노이즈라 제외). 민감도 순 정렬.
function labelBadges(labels?: string[]): string[] {
  return (labels ?? []).filter((l) => l in LABEL_META)
                       .sort((a, b) => LABEL_ORDER.indexOf(a) - LABEL_ORDER.indexOf(b))
}

// LabelChip — 의미 라벨 배지 한 개(행·분포·필터 공용).
function LabelChip({ label, dim = false, children }: { label: string; dim?: boolean; children?: React.ReactNode }) {
  const c = LABEL_META[label]
  return (
    <span className="inline-flex shrink-0 items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium"
          style={{ color: c, background: dim ? 'transparent' : `color-mix(in srgb, ${c} 14%, transparent)`,
                   boxShadow: dim ? `inset 0 0 0 1px color-mix(in srgb, ${c} 35%, transparent)` : undefined }}>
      {label}{children}
    </span>
  )
}

// LabelBadges — 행의 의미 라벨. 상한을 넘으면 "+N" 하나로 접는다 (#43).
function LabelBadges({ labels }: { labels?: string[] }) {
  const tr = useT()
  const ls = labelBadges(labels)
  if (ls.length === 0) return null
  const rest = ls.slice(MAX_ROW_LABELS)
  return (
    <>
      {ls.slice(0, MAX_ROW_LABELS).map((l) => (
        <Tooltip key={l} label={tr('recon.tree.labelHint')}><LabelChip label={l} /></Tooltip>
      ))}
      {rest.length > 0 && (
        <Tooltip label={rest.join(', ')}>
          <span className="shrink-0 rounded border border-[var(--border)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--muted)]">+{rest.length}</span>
        </Tooltip>
      )}
    </>
  )
}
// sourceMeta — 빈 문자열(레거시 프록시 캡처)은 traffic 으로 본다 (#26 등급 규칙과 정합).
// methodColor — HTTP 메서드 색. 읽기(GET/HEAD)는 차분하게, 쓰기·삭제는 경고색으로 (#28 가독성).
function methodColor(m: string): string {
  const u = m.toUpperCase()
  if (u === 'DELETE') return 'var(--red)'
  if (u === 'POST' || u === 'PUT' || u === 'PATCH') return 'var(--amber)'
  return 'var(--accent)' // GET·HEAD·OPTIONS
}

function sourceMeta(src?: string) {
  return SOURCE_META[src || 'traffic'] ?? SOURCE_META['traffic']
}

function EndpointTree({ targets }: { targets: Target[] | null }) {
  const tr = useT() // 콜백 파라미터 t(Target)와의 섀도잉 회피
  const [q, setQ] = useState('')
  const [method, setMethod] = useState('')
  const [authOnly, setAuthOnly] = useState(false)
  const [verdictOnly, setVerdictOnly] = useState(false)
  const [showUnverified, setShowUnverified] = useState(false) // 기본 verified 만 (#28)
  const [behindAuth, setBehindAuth] = useState(false) // 인증 뒤에만 보이는 표면만 (#38)
  const [label, setLabel] = useState('') // 의미 라벨 필터 (#43)
  const [open, setOpen] = useState<string | null>(null)

  const all = targets ?? []
  const methods = Array.from(new Set(all.flatMap((t) => t.methods ?? []))).sort()
  const unverifiedCount = all.filter((t) => t.unverified).length
  const authOnlyCount = all.filter((t) => t.auth_only).length
  const hasFilter = !!(q || method || authOnly || verdictOnly || showUnverified || behindAuth || label)

  const filtered = all.filter((t) => {
    if (!showUnverified && t.unverified) return false // 라이브니스 미통과 기본 숨김 (#28)
    if (q && !`${t.host}${t.path}`.toLowerCase().includes(q.toLowerCase())) return false
    if (method && !(t.methods ?? []).includes(method)) return false
    if (authOnly && !t.auth_required) return false
    if (behindAuth && !t.auth_only) return false // 인증 뒤에만 보이는 표면 (#38)
    if (label && !(t.labels ?? []).includes(label)) return false // 의미 라벨 (#43)
    if (verdictOnly && !t.verdict) return false
    return true
  })

  // 출처 분포 — verified 만 대상(표시 기준과 일치). #28 요약 지표.
  const dist: Record<string, number> = {}
  for (const t of all) if (!t.unverified) dist[t.source || 'traffic'] = (dist[t.source || 'traffic'] ?? 0) + 1

  // 라벨 분포 — 출처 분포와 같은 기준(verified). 칩이 곧 필터다 (#43).
  const labelDist: Record<string, number> = {}
  for (const t of all) if (!t.unverified) for (const l of labelBadges(t.labels)) labelDist[l] = (labelDist[l] ?? 0) + 1
  const labelKeys = LABEL_ORDER.filter((l) => labelDist[l])

  const byHost: Record<string, Target[]> = {}
  for (const t of filtered) (byHost[t.host] ??= []).push(t)

  const count = targets ? (hasFilter ? `${filtered.length}/${all.length}` : `${all.length}`) : ''
  const inp = 'rounded-lg border border-[var(--border)] bg-[var(--panel-2)] px-2 py-1.5 text-xs'

  return (
    <Card title={`${tr('recon.tree.title')}${count ? ` (${count})` : ''}`} icon={Network}>
      {/* 필터 바 */}
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="relative min-w-[180px] flex-1">
          <Search size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--muted)]" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder={tr('recon.tree.searchPlaceholder')}
                 className="w-full rounded-lg border border-[var(--border)] bg-[var(--panel-2)] py-1.5 pl-8 pr-3 font-mono text-xs" />
        </div>
        <select value={method} onChange={(e) => setMethod(e.target.value)} className={inp} aria-label={tr('recon.tree.methodFilter')}>
          <option value="">{tr('recon.tree.allMethods')}</option>
          {methods.map((m) => <option key={m} value={m}>{m}</option>)}
        </select>
        <button onClick={() => setAuthOnly((v) => !v)}
                className={`inline-flex items-center gap-1 rounded-lg border px-2 py-1.5 text-xs ${authOnly ? 'border-[var(--amber)] text-[var(--amber)]' : 'border-[var(--border)] text-[var(--muted)]'}`}>
          <KeyRound size={12} /> {tr('recon.tree.auth')}
        </button>
        <button onClick={() => setVerdictOnly((v) => !v)}
                className={`rounded-lg border px-2 py-1.5 text-xs ${verdictOnly ? 'border-[var(--red)] text-[var(--red)]' : 'border-[var(--border)] text-[var(--muted)]'}`}>
          {tr('recon.tree.verdict')}
        </button>
        {unverifiedCount > 0 && (
          <button onClick={() => setShowUnverified((v) => !v)}
                  title={tr('recon.tree.unverifiedHint')}
                  className={`inline-flex items-center gap-1 rounded-lg border px-2 py-1.5 text-xs ${showUnverified ? 'border-[var(--amber)] text-[var(--amber)]' : 'border-[var(--border)] text-[var(--muted)]'}`}>
            <ShieldCheck size={12} /> {tr('recon.tree.showUnverified')} ({unverifiedCount})
          </button>
        )}
        {authOnlyCount > 0 && (
          <button onClick={() => setBehindAuth((v) => !v)}
                  title={tr('recon.tree.authOnlyHint')}
                  className={`inline-flex items-center gap-1 rounded-lg border px-2 py-1.5 text-xs ${behindAuth ? 'border-[var(--red)] text-[var(--red)]' : 'border-[var(--border)] text-[var(--muted)]'}`}>
            <ShieldCheck size={12} /> {tr('recon.tree.authOnly')} ({authOnlyCount})
          </button>
        )}
      </div>

      {/* 출처 분포 — verified 기준 (#28) */}
      {Object.keys(dist).length > 0 && (
        <div className="mb-3 flex flex-wrap items-center gap-1.5 text-[11px] text-[var(--muted)]">
          <span className="inline-flex items-center gap-1">{tr('recon.tree.sources')}: <InfoTip label={tr('recon.source.help')} /></span>
          {Object.entries(dist).sort((a, b) => b[1] - a[1]).map(([src, n]) => {
            const m = sourceMeta(src)
            return <Tooltip key={src} label={tr(`recon.source.${m.key}`)}>
                     <span className="inline-flex items-center gap-1 rounded px-1.5 py-0.5"
                           style={{ color: m.color, background: `color-mix(in srgb, ${m.color} 12%, transparent)` }}>{m.label} {n}</span>
                   </Tooltip>
          })}
          {unverifiedCount > 0 && <Tooltip label={tr('recon.tree.unverifiedHint')}><span className="text-[var(--muted)]">· {tr('recon.tree.unverifiedCount')} {unverifiedCount}</span></Tooltip>}
        </div>
      )}

      {/* 라벨 분포 = 라벨 필터 (#43). 칩을 누르면 그 라벨만 남는다 — 분포와 필터를 한 줄에 둬
          "결제가 몇 건인가"와 "결제만 보자"가 같은 동작이 된다. */}
      {labelKeys.length > 0 && (
        <div className="mb-3 flex flex-wrap items-center gap-1.5 text-[11px] text-[var(--muted)]">
          <span className="inline-flex items-center gap-1">{tr('recon.tree.labels')}: <InfoTip label={tr('recon.tree.labelHint')} /></span>
          {labelKeys.map((l) => (
            <button key={l} type="button" onClick={() => setLabel(label === l ? '' : l)}
                    aria-pressed={label === l}
                    title={tr(`recon.label.${l}`)}
                    className={`rounded ${label === l ? '' : 'opacity-70 hover:opacity-100'}`}>
              <LabelChip label={l} dim={label !== l}>
                <span className="tabular-nums">{labelDist[l]}</span>
              </LabelChip>
            </button>
          ))}
          {label && (
            <button type="button" onClick={() => setLabel('')} className="underline">{tr('recon.tree.clearLabel')}</button>
          )}
        </div>
      )}

      {!targets || all.length === 0 ? (
        <Empty icon={Network}>{tr('recon.tree.emptyNone')}</Empty>
      ) : filtered.length === 0 ? (
        <Empty icon={Search}>{tr('recon.tree.emptyFilter')}</Empty>
      ) : (
        <div className="space-y-4">
          {Object.entries(byHost).map(([host, eps]) => (
            <div key={host}>
              <div className="mb-1.5 flex items-center gap-2 font-mono text-xs font-semibold text-[var(--muted)]">
                <Globe size={13} /> {host}
              </div>
              <div className="overflow-hidden rounded-lg border border-[var(--border)]">
                {eps.map((t, i) => {
                  const key = `${host}${t.path}${i}`
                  const isOpen = open === key
                  return (
                    <div key={key} className="border-t border-[var(--border)] first:border-t-0">
                      <button onClick={() => setOpen(isOpen ? null : key)}
                              className="flex w-full items-center gap-2.5 px-3 py-2 text-left hover:bg-[var(--panel-2)]">
                        <ChevronRight size={13} className={`shrink-0 text-[var(--muted)] transition-transform ${isOpen ? 'rotate-90' : ''}`} />
                        {/* 메서드 — 고정폭 컬럼(경로 시작을 일렬로) */}
                        <span className="flex shrink-0 flex-wrap justify-end gap-1" style={{ minWidth: '3rem' }}>
                          {(t.methods ?? []).map((m) => (
                            <span key={m} className="rounded px-1.5 py-0.5 text-[10px] font-bold"
                                  style={{ color: methodColor(m), background: `color-mix(in srgb, ${methodColor(m)} 14%, transparent)` }}>{m}</span>
                          ))}
                        </span>
                        {/* 경로 + 출처 — 남는 폭을 채우고 경로는 잘림 처리 */}
                        <span className="flex min-w-0 flex-1 items-center gap-2">
                          <span className="truncate font-mono text-sm">{t.path}</span>
                          {(() => { const m = sourceMeta(t.source); return (
                            <Tooltip label={tr(`recon.source.${m.key}`)}>
                              <span className="shrink-0 rounded px-1.5 py-0.5 text-[10px] font-medium"
                                    style={{ color: m.color, background: `color-mix(in srgb, ${m.color} 14%, transparent)` }}>{m.label}</span>
                            </Tooltip>
                          ) })()}
                          {t.unverified && (
                            <Tooltip label={tr('recon.tree.unverifiedHint')}>
                              <span className="shrink-0 rounded px-1.5 py-0.5 text-[10px] font-medium text-[var(--amber)]"
                                    style={{ background: 'color-mix(in srgb, var(--amber) 14%, transparent)' }}>unverified</span>
                            </Tooltip>
                          )}
                          {t.auth_only && (
                            <Tooltip label={tr('recon.tree.authOnlyHint')}>
                              <span className="shrink-0 rounded px-1.5 py-0.5 text-[10px] font-medium text-[var(--red)]"
                                    style={{ background: 'color-mix(in srgb, var(--red) 14%, transparent)' }}>auth-only</span>
                            </Tooltip>
                          )}
                          <LabelBadges labels={t.labels} />
                        </span>
                        {/* 메타 — 우측 정렬로 모음 */}
                        <span className="flex shrink-0 items-center gap-2.5 text-[11px] text-[var(--muted)]">
                          {t.auth_required && <KeyRound size={12} className="text-[var(--amber)]" />}
                          {t.verdict && <Badge text={t.verdict} color="var(--red)" />}
                          {t.params && t.params.length > 0 && <span>{t.params.length}p</span>}
                          {typeof t.count === 'number' && t.count > 0 && <span className="tabular-nums">{t.count} hits</span>}
                        </span>
                      </button>
                      {isOpen && (
                        <div className="border-t border-[var(--border)] bg-[var(--panel-2)] px-3 py-2.5 pl-8 text-xs">
                          <div className="mb-2 flex flex-wrap gap-x-5 gap-y-1 text-[var(--muted)]">
                            <span>{tr('recon.tree.hits')} <b className="text-[var(--text)]">{t.count ?? 0}</b></span>
                            <span className="inline-flex items-center gap-1"><Clock size={11} /> {tr('recon.tree.first')} <b className="text-[var(--text)]">{fmtTime(t.first_seen)}</b></span>
                            <span className="inline-flex items-center gap-1"><Clock size={11} /> {tr('recon.tree.last')} <b className="text-[var(--text)]">{fmtTime(t.last_seen)}</b></span>
                            <span>{tr('recon.tree.authLabel')} <b className="text-[var(--text)]">{t.auth_required ? tr('recon.tree.needed') : '—'}</b></span>
                          </div>
                          {t.verdict && <div className="mb-2 text-[var(--muted)]">{tr('recon.tree.verdictLabel')}: <span className="text-[var(--text)]">{t.verdict}</span></div>}
                          {t.params && t.params.length > 0 ? (
                            <div className="overflow-x-auto">
                              <table className="w-full border-collapse text-[11px]">
                                <thead>
                                  <tr className="text-left text-[var(--muted)]">
                                    <th className="py-1 pr-3 font-medium">{tr('recon.tree.colIn')}</th>
                                    <th className="py-1 pr-3 font-medium">{tr('recon.tree.colName')}</th>
                                    <th className="py-1 pr-3 font-medium">{tr('recon.tree.colType')}</th>
                                    <th className="py-1 pr-3 font-medium">{tr('recon.tree.required')}</th>
                                    <th className="py-1 font-medium">{tr('recon.tree.colSample')}</th>
                                  </tr>
                                </thead>
                                <tbody className="font-mono">
                                  {t.params.map((p) => (
                                    <tr key={p.in + p.name} className="border-t border-[var(--border)]">
                                      <td className="py-1 pr-3 text-[var(--muted)]">{p.in}</td>
                                      <td className="py-1 pr-3">
                                        {p.name}
                                        {p.mined && <span className="ml-1.5 rounded px-1 py-0.5 text-[9px] font-semibold" style={{ background: 'var(--amber)', color: '#000' }} title={tr('recon.tree.minedHint')}>{tr('recon.tree.mined')}</span>}
                                      </td>
                                      <td className="py-1 pr-3 text-[var(--muted)]">{p.type ?? '—'}</td>
                                      <td className="py-1 pr-3">{p.required ? <span className="text-[var(--red)]">{tr('recon.tree.required')}</span> : '—'}</td>
                                      <td className="py-1 text-[var(--muted)]">{p.sample ?? '—'}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          ) : <div className="text-[var(--muted)]">{tr('recon.tree.noParams')}</div>}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}

// ReconSteps — 정찰 워크플로 안내 (#28 UX). 처음 사용자가 "무엇을 먼저 하는지" 를 4단계로 본다.
// 각 단계는 현재 상태를 반영한다(스코프 N · 엔드포인트 N) — 지금 어디쯤인지 감이 잡힌다.
function ReconSteps({ stats, targets }: { stats: Stats | null; targets: Target[] | null }) {
  const t = useT()
  const scopeN = stats?.scope?.length ?? 0
  const epN = targets?.length ?? 0
  const steps = [
    { icon: Globe, key: 'scope', done: scopeN > 0, meta: `${scopeN} host` },
    { icon: Radar, key: 'traffic', done: epN > 0, meta: '' },
    { icon: Crosshair, key: 'endpoints', done: epN > 0, meta: epN > 0 ? `${epN} eps` : '' },
    { icon: ScanLine, key: 'scan', done: (stats?.scanruns ?? 0) > 0, meta: '' },
  ]
  return (
    <Card pad={false} className="overflow-hidden">
      <div className="flex flex-col divide-y divide-[var(--border)] sm:flex-row sm:divide-x sm:divide-y-0">
        {steps.map((st, i) => {
          const Icon = st.icon
          return (
            <div key={st.key} className="flex flex-1 items-center gap-3 px-4 py-3">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-xs font-bold"
                   style={{ color: st.done ? 'var(--green)' : 'var(--muted)',
                            background: st.done ? 'color-mix(in srgb, var(--green) 16%, transparent)' : 'var(--panel-2)' }}>
                {st.done ? <Check size={15} /> : i + 1}
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-1.5 text-sm font-medium">
                  <Icon size={13} className="text-[var(--muted)]" /> {t(`recon.steps.${st.key}.title`)}
                  {st.meta && <span className="text-[11px] text-[var(--muted)]">· {st.meta}</span>}
                </div>
                <div className="truncate text-[11px] text-[var(--muted)]">{t(`recon.steps.${st.key}.desc`)}</div>
              </div>
            </div>
          )
        })}
      </div>
    </Card>
  )
}

// RegMapCard — 정찰 규제 매핑 (이슈 #42): 의미 라벨 → 점검항목 후보. 라벨이 없으면 숨김.
function RegMapCard() {
  const t = useT()
  const { data } = usePoll<ReconRegmap>('/api/recon/regmap', 6000)
  if (!data || data.labeled === 0) return null
  // 커버리지 — 라벨로 도달 가능한 점검항목(모수) 중 실제 후보가 나온 비율. 공백은 그 나머지다.
  const covered = (data.schemes ?? []).reduce((n, s) => n + s.applicable, 0)
  const mappable = (data.schemes ?? []).reduce((n, s) => n + s.mappable, 0)
  return (
    <Card title={t('recon.regmap.title')} icon={ClipboardCheck} collapsible defaultOpen muted
          right={<span className="hidden text-[11px] text-[var(--muted)] md:inline">{t('recon.regmap.subtitle')}</span>}>
      <div className="mb-2.5 flex flex-wrap items-center gap-3 text-xs">
        <span className="text-[var(--muted)]">{t('recon.regmap.labeled')} <b className="text-[var(--text)]">{data.labeled}</b> / {data.endpoints}</span>
        {mappable > 0 && (
          <Tooltip label={t('recon.regmap.coverHint')}>
            <span className="text-[var(--muted)]">{t('recon.regmap.covered')} <b className="text-[var(--text)]">{covered}</b> / {mappable}</span>
          </Tooltip>
        )}
        {mappable - covered > 0 && (
          <Tooltip label={t('recon.regmap.gapHint')}>
            <span className="rounded px-1.5 py-0.5 font-medium text-[var(--amber)]" style={{ background: 'color-mix(in srgb, var(--amber) 14%, transparent)' }}>
              {t('recon.regmap.gap')} {mappable - covered}
            </span>
          </Tooltip>
        )}
        {data.access_control_candidates > 0 && (
          <Tooltip label={t('recon.regmap.acHint')}>
            <span className="rounded px-1.5 py-0.5 font-medium text-[var(--red)]" style={{ background: 'color-mix(in srgb, var(--red) 14%, transparent)' }}>
              {t('recon.regmap.accessCtl')} {data.access_control_candidates}
            </span>
          </Tooltip>
        )}
      </div>
      <div className="space-y-3">
        {data.schemes?.map((s) => (
          <div key={s.scheme}>
            <div className="mb-1.5 flex items-baseline gap-2 text-xs">
              <span className="font-semibold">{s.scheme}</span>
              <span className="text-[var(--muted)]">{t('recon.regmap.applicable')} {s.applicable} / {s.mappable}</span>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {s.items.map((it) => (
                <Tooltip key={it.check_item.id} label={`${it.vuln_name} · ${it.labels.join(', ')}`}>
                  <span className="inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px]"
                        style={{ borderColor: it.access_control ? 'var(--red)' : 'var(--border)', color: it.access_control ? 'var(--red)' : 'var(--muted)' }}>
                    <b className="text-[var(--text)]">{it.check_item.id}</b>
                    <span className="tabular-nums">{it.count}</span>
                  </span>
                </Tooltip>
              ))}
            </div>
            {/* 공백 — 라벨로 닿을 수 있는데 아직 발견 0건. 툴팁의 라벨이 "무엇을 더 찾으면 메워지는가"다. */}
            {s.gaps && s.gaps.length > 0 && (
              <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                <span className="text-[10px] text-[var(--amber)]">{t('recon.regmap.gap')} {s.gaps.length}</span>
                {s.gaps.map((it) => (
                  <Tooltip key={it.check_item.id} label={`${it.vuln_name} · ${t('recon.regmap.gapNeeds')}: ${it.labels.join(', ')}`}>
                    <span className="inline-flex items-center gap-1 rounded border border-dashed px-1.5 py-0.5 text-[10px] text-[var(--muted)]"
                          style={{ borderColor: 'var(--border)' }}>
                      <span>{it.check_item.id}</span>
                      <span className="tabular-nums">0</span>
                    </span>
                  </Tooltip>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </Card>
  )
}

export function Recon() {
  const t = useT()
  const { data: targets } = usePoll<Target[]>('/api/endpoints?include_unverified=true', 4000)
  const { data: rules } = usePoll<Rule[]>('/api/rules', 8000)
  const { data: stats } = usePoll<Stats>('/api/stats', 5000)
  const { data: auth } = usePoll<AuthSummary>('/api/auth', 8000)

  return (
    <div className="space-y-5">
      {/* 워크플로 안내 (#28) — 전체 너비 */}
      <ReconSteps stats={stats} targets={targets} />

      <div className="grid gap-5 lg:grid-cols-[2fr_1fr]">
      {/* 좌측: 액션 — 트래픽 수집·엔드포인트 (FR-2.4) */}
      <div className="space-y-5">
        <ProxyTool stats={stats} />
        <CrawlExplore />
        <EndpointTree targets={targets} />
        <RegMapCard />
      </div>

      {/* 우측: 참고 — 파이프라인·스코프·인증 (#28: 기본 접힘, 필요 시 펼침) */}
      <div className="space-y-5">
        {/* 판단 파이프라인 (FR-2.2) */}
        <Card title={t('recon.pipe.title')} icon={Filter} collapsible defaultOpen muted>
          <div className="mb-3 flex items-center gap-2 text-xs">
            <Stage label={t('recon.pipe.scope')} sub="hard" tip={t('recon.pipe.scopeTip')} />
            <Arrow />
            <Stage label={t('recon.pipe.rule')} sub={`${rules?.length ?? 0} rules`} tip={t('recon.pipe.ruleTip')} />
            <Arrow />
            <Stage label="LLM" sub={stats?.llm_provider ?? '—'} tip={t('recon.pipe.llmTip')} />
            <Arrow />
            <Stage label={t('recon.pipe.forward')} sub="capture" tip={t('recon.pipe.forwardTip')} />
          </div>
          <div className="space-y-1">
            {(rules ?? []).map((r, i) => (
              <div key={i} className="flex items-center gap-2 rounded-lg px-2 py-1.5 text-xs hover:bg-[var(--panel-2)]">
                <Badge text={r.action} color={r.action === 'block' ? 'var(--red)' : 'var(--green)'} />
                <span className="font-mono text-[var(--muted)]">{(r.methods ?? []).join('/') || '*'}</span>
                <span className="font-mono truncate flex-1">{r.path_pattern || '*'}</span>
              </div>
            ))}
            {(!rules || rules.length === 0) && <Empty>{t('recon.pipe.noRules')}</Empty>}
          </div>
        </Card>

        {/* 스코프 (FR-2.1) */}
        <Card title={t('recon.scope.title')} icon={Globe} collapsible defaultOpen={false} muted>
          <div className="flex flex-wrap gap-1.5">
            {(stats?.scope ?? []).map((s) => (
              <span key={s} className="rounded-md border border-[var(--border)] px-2 py-0.5 font-mono text-xs">{s}</span>
            ))}
          </div>
        </Card>

        {/* 인증·신원 (FR-2.5 / FR-3.6) */}
        <Card title={t('recon.authid.title')} icon={KeyRound} collapsible defaultOpen={false} muted>
          <div className="flex items-center justify-between text-sm">
            <span className="text-[var(--muted)]">{t('recon.authid.sessionInjection')}</span>
            <Dot text={auth?.enabled ? t('common.enabled') : t('common.off')} color={auth?.enabled ? 'var(--green)' : 'var(--muted)'} />
          </div>
          {auth && (auth.cookies?.length || auth.headers?.length) ? (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {(auth.cookies ?? []).map((c) => <Badge key={c} text={`cookie:${c}`} color="var(--blue)" />)}
              {(auth.headers ?? []).map((h) => <Badge key={h} text={`hdr:${h}`} color="var(--blue)" />)}
            </div>
          ) : null}
          <div className="mt-3 border-t border-[var(--border)] pt-2.5">
            <div className="eyebrow mb-1.5 flex items-center gap-1.5"><ShieldCheck size={12} /> {t('recon.auth.identities')}</div>
            {auth?.identities?.length ? (
              <div className="space-y-1">
                {auth.identities.map((id) => (
                  <div key={id.name} className="flex items-center justify-between text-sm">
                    <span className="font-medium">{id.name}</span>
                    <span className="text-xs text-[var(--muted)]">{id.cookies.length + id.headers.length} creds</span>
                  </div>
                ))}
              </div>
            ) : <div className="text-xs text-[var(--muted)]">{t('recon.auth.noIdentities')}</div>}
          </div>
        </Card>

        <LoginSeqCard />
      </div>
      </div>
    </div>
  )
}

// LoginSeqCard — 세션 지속성(FR-2.5): 만료 시 자동 재로그인 절차 설정. 값은 마스킹, 저장은 리더 전용.
function LoginSeqCard() {
  const t = useT()
  const { data: info } = usePoll<LoginSeqInfo>('/api/login-seq', 10000)
  const [open, setOpen] = useState(false)
  const [url, setUrl] = useState('')
  const [loggedOut, setLoggedOut] = useState('')
  const [tokenURL, setTokenURL] = useState('')
  const [tokenField, setTokenField] = useState('')
  const [rows, setRows] = useState<{ k: string; v: string }[]>([{ k: 'username', v: '' }, { k: 'password', v: '' }])
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')

  // 편집 열 때 현재 설정(값 제외)으로 프리필.
  function edit() {
    if (info) {
      setUrl(info.url); setLoggedOut(info.logged_out); setTokenURL(info.token_url); setTokenField(info.token_field)
      if (info.fields.length) setRows(info.fields.map((k) => ({ k, v: '' })))
    }
    setOpen(true); setMsg(''); setErr('')
  }

  async function save() {
    setBusy(true); setMsg(''); setErr('')
    const fields: Record<string, string> = {}
    for (const r of rows) if (r.k.trim()) fields[r.k.trim()] = r.v
    try {
      await apiPost('/api/login-seq', {
        url, method: 'POST', logged_out: loggedOut,
        token_url: tokenURL, token_field: tokenField, token_param: tokenField, fields,
      })
      setMsg(t('recon.loginseq.saved')); setOpen(false)
    } catch (e) { setErr(String(e)) } finally { setBusy(false) }
  }

  const inp = 'w-full rounded-lg border border-[var(--border)] bg-[var(--panel-2)] px-2 py-1 text-xs'

  return (
    <Card title={t('recon.loginseq.title')} icon={KeyRound}
          right={<Dot text={info?.enabled ? t('common.enabled') : t('common.off')} color={info?.enabled ? 'var(--green)' : 'var(--muted)'} />}>
      <p className="mb-2 text-[11px] text-[var(--muted)]">
        {t('recon.loginseq.desc1')}<b className="text-[var(--text)]">{t('recon.loginseq.expiryMark')}</b>{t('recon.loginseq.desc2')}
      </p>
      {!open ? (
        <div className="space-y-1.5 text-xs">
          {info?.url ? (
            <>
              <Row2 k="URL" v={info.url} />
              <Row2 k={t('recon.loginseq.expiryMarkShort')} v={info.logged_out || '—'} />
              <Row2 k={t('recon.loginseq.fields')} v={info.fields.join(', ') || '—'} />
              {info.token_field && <Row2 k={t('recon.loginseq.csrf')} v={info.token_field} />}
            </>
          ) : <div className="text-[var(--muted)]">{t('recon.loginseq.notSet')}</div>}
          <button onClick={edit} className="mt-1 rounded-lg border border-[var(--border)] px-2.5 py-1 text-xs font-semibold">
            {info?.url ? t('common.edit') : t('recon.loginseq.setup')}
          </button>
          {msg && <div className="text-[11px]" style={{ color: 'var(--green)' }}>{msg}</div>}
        </div>
      ) : (
        <div className="space-y-2">
          <label className="block"><span className="eyebrow">{t('recon.loginseq.loginUrl')}</span>
            <input className={inp} value={url} onChange={(e) => setUrl(e.target.value)} placeholder="http://target/login.php" /></label>
          <label className="block"><span className="eyebrow">{t('recon.loginseq.expiryMarkRegex')}</span>
            <input className={inp} value={loggedOut} onChange={(e) => setLoggedOut(e.target.value)} placeholder="(?i)login\.php|please log in" /></label>
          <div>
            <span className="eyebrow">{t('recon.loginseq.formFields')}</span>
            {rows.map((r, i) => (
              <div key={i} className="mt-1 flex gap-1">
                <input className={inp + ' w-1/3'} value={r.k} placeholder="name"
                       onChange={(e) => setRows(rows.map((x, j) => j === i ? { ...x, k: e.target.value } : x))} />
                <input className={inp} type={/pass|pw|secret/i.test(r.k) ? 'password' : 'text'} value={r.v} placeholder="value" autoComplete="off"
                       onChange={(e) => setRows(rows.map((x, j) => j === i ? { ...x, v: e.target.value } : x))} />
                <button className="px-1 text-[var(--muted)]" onClick={() => setRows(rows.filter((_, j) => j !== i))}>✕</button>
              </div>
            ))}
            <button className="mt-1 text-[11px] text-[var(--muted)] underline" onClick={() => setRows([...rows, { k: '', v: '' }])}>{t('recon.loginseq.addField')}</button>
          </div>
          <details className="text-xs">
            <summary className="cursor-pointer text-[var(--muted)]">{t('recon.loginseq.csrfOptional')}</summary>
            <label className="mt-1 block"><span className="eyebrow">{t('recon.loginseq.tokenUrl')}</span>
              <input className={inp} value={tokenURL} onChange={(e) => setTokenURL(e.target.value)} placeholder="http://target/login.php" /></label>
            <label className="mt-1 block"><span className="eyebrow">{t('recon.loginseq.tokenInput')}</span>
              <input className={inp} value={tokenField} onChange={(e) => setTokenField(e.target.value)} placeholder="user_token" /></label>
          </details>
          <div className="flex items-center gap-2">
            <button onClick={save} disabled={busy || !url || !loggedOut}
                    className="rounded-lg px-3 py-1.5 text-xs font-semibold disabled:opacity-50"
                    style={{ background: 'var(--accent)', color: 'var(--accent-fg)' }}>{busy ? t('common.saving') : t('common.save')}</button>
            <button onClick={() => setOpen(false)} className="text-xs text-[var(--muted)]">{t('common.cancel')}</button>
          </div>
          {err && <div className="text-[11px]" style={{ color: 'var(--red)' }}>{t('recon.loginseq.saveFail')}: {err}</div>}
          <p className="text-[10px] text-[var(--muted)]">{t('recon.loginseq.note')}</p>
        </div>
      )}
    </Card>
  )
}

function Row2({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex items-start justify-between gap-2">
      <span className="text-[var(--muted)]">{k}</span>
      <span className="max-w-[60%] truncate text-right font-mono">{v}</span>
    </div>
  )
}

function Stage({ label, sub, tip }: { label: string; sub: string; tip?: string }) {
  const body = (
    <div className="flex-1 rounded-lg border border-[var(--border)] bg-[var(--panel-2)] px-2 py-1.5 text-center">
      <div className="text-[11px] font-semibold">{label}</div>
      <div className="text-[9px] text-[var(--muted)]">{sub}</div>
    </div>
  )
  return tip ? <Tooltip label={tip} className="flex-1">{body}</Tooltip> : body
}
function Arrow() { return <span className="text-[var(--muted)]">→</span> }
