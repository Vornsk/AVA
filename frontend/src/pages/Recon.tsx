import { useState } from 'react'
import { Network, Filter, Globe, KeyRound, ShieldCheck, Radar, Play, Search, ChevronRight, Clock } from 'lucide-react'
import { usePoll, apiPost, type Target, type Rule, type Stats, type AuthSummary, type CrawlResult, type LoginSeqInfo } from '../api'
import { Card, Badge, Dot, Empty } from '../components/ui'

// fmtTime — RFC3339 시각을 로캘 표기로. 값 없으면 —.
function fmtTime(s?: string) {
  if (!s) return '—'
  const d = new Date(s)
  return isNaN(d.getTime()) ? s : d.toLocaleString()
}

// CrawlExplore — 자동 공격면 탐색(AppScan Explore 대응). 시작 URL에서 링크·폼을 따라 자동 크롤.
function CrawlExplore() {
  const [seed, setSeed] = useState('')
  const [busy, setBusy] = useState(false)
  const [headless, setHeadless] = useState(false)
  const { data: runs } = usePoll<CrawlResult[]>('/api/crawl', 2000)
  const { data: modes } = usePoll<{ headless_available: boolean }>('/api/crawl-modes', 30000)
  const hlOK = modes?.headless_available === true
  const latest = runs && runs.length ? runs[runs.length - 1] : null
  const running = latest?.status === '진행'

  async function start() {
    if (!seed.trim()) return
    setBusy(true)
    try { await apiPost('/api/crawl', { seed: seed.trim(), mode: headless ? 'headless' : 'static' }) }
    catch (e) { alert('크롤 시작 실패: ' + e) } finally { setBusy(false) }
  }

  return (
    <Card title="자동 크롤 (Explore)" icon={Radar}
          right={<span className="hidden text-[11px] text-[var(--muted)] md:inline">링크·폼·JS를 따라 스코프 내를 자동 탐색</span>}>
      <div className="flex gap-2">
        <input value={seed} onChange={(e) => setSeed(e.target.value)}
               onKeyDown={(e) => e.key === 'Enter' && start()}
               placeholder="시작 URL — 예: http://127.0.0.1:4280/ (스코프 내)"
               className="flex-1 rounded-lg border border-[var(--border)] bg-[var(--panel-2)] px-3 py-1.5 font-mono text-xs" />
        <button onClick={start} disabled={busy || running}
                className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold disabled:opacity-50"
                style={{ background: 'var(--accent)', color: 'var(--accent-fg)' }}>
          <Play size={13} /> {busy ? '시작 중…' : running ? '진행 중…' : '크롤 시작'}
        </button>
      </div>
      <label className={`mt-2 flex items-center gap-1.5 text-xs ${hlOK ? 'cursor-pointer text-[var(--muted)]' : 'text-[var(--muted)] opacity-50'}`}
             title={hlOK ? 'Chrome로 JS를 실행해 SPA까지 완전 크롤(느림). 렌더된 DOM+XHR/fetch까지 수집' : '이 서버에 Chrome/Chromium이 없어 사용 불가'}>
        <input type="checkbox" checked={headless && hlOK} disabled={!hlOK} onChange={(e) => setHeadless(e.target.checked)} />
        헤드리스(JS 실행) 크롤 {hlOK ? <span style={{ color: 'var(--green)' }}>· 사용 가능</span> : <span>· Chrome 없음</span>}
      </label>
      {latest && (
        <div className="mt-2.5 flex flex-wrap items-center gap-3 text-xs">
          <Dot text={latest.status} color={latest.status === '진행' ? 'var(--amber)' : latest.status === '완료' ? 'var(--green)' : 'var(--muted)'} />
          {latest.mode === 'headless' && <Badge text="headless" color="var(--blue)" />}
          <span className="text-[var(--muted)]"><b className="text-[var(--text)]">{latest.pages}</b> 페이지</span>
          <span className="text-[var(--muted)]">발견 <b className="text-[var(--text)]">{latest.found}</b></span>
          {latest.js > 0 && <span className="text-[var(--muted)]">JS <b className="text-[var(--text)]">{latest.js}</b></span>}
          <span className="text-[var(--muted)]">대기 {latest.queued}</span>
          {latest.errors > 0 && <span style={{ color: 'var(--amber)' }}>오류 {latest.errors}</span>}
          <span className="font-mono text-[10px] text-[var(--muted)]">{latest.seed}</span>
        </div>
      )}
    </Card>
  )
}

// EndpointTree — 캡처된 공격면 조회 (이슈 #7): 검색·메서드·인증·판정 필터 + 행 클릭 상세 드릴다운.
function EndpointTree({ targets }: { targets: Target[] | null }) {
  const [q, setQ] = useState('')
  const [method, setMethod] = useState('')
  const [authOnly, setAuthOnly] = useState(false)
  const [verdictOnly, setVerdictOnly] = useState(false)
  const [open, setOpen] = useState<string | null>(null)

  const all = targets ?? []
  const methods = Array.from(new Set(all.flatMap((t) => t.methods ?? []))).sort()
  const hasFilter = !!(q || method || authOnly || verdictOnly)

  const filtered = all.filter((t) => {
    if (q && !`${t.host}${t.path}`.toLowerCase().includes(q.toLowerCase())) return false
    if (method && !(t.methods ?? []).includes(method)) return false
    if (authOnly && !t.auth_required) return false
    if (verdictOnly && !t.verdict) return false
    return true
  })

  const byHost: Record<string, Target[]> = {}
  for (const t of filtered) (byHost[t.host] ??= []).push(t)

  const count = targets ? (hasFilter ? `${filtered.length}/${all.length}` : `${all.length}`) : ''
  const inp = 'rounded-lg border border-[var(--border)] bg-[var(--panel-2)] px-2 py-1.5 text-xs'

  return (
    <Card title={`Endpoint Tree${count ? ` (${count})` : ''}`} icon={Network}>
      {/* 필터 바 */}
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="relative min-w-[180px] flex-1">
          <Search size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--muted)]" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="호스트·경로 검색"
                 className="w-full rounded-lg border border-[var(--border)] bg-[var(--panel-2)] py-1.5 pl-8 pr-3 font-mono text-xs" />
        </div>
        <select value={method} onChange={(e) => setMethod(e.target.value)} className={inp} aria-label="메서드 필터">
          <option value="">모든 메서드</option>
          {methods.map((m) => <option key={m} value={m}>{m}</option>)}
        </select>
        <button onClick={() => setAuthOnly((v) => !v)}
                className={`inline-flex items-center gap-1 rounded-lg border px-2 py-1.5 text-xs ${authOnly ? 'border-[var(--amber)] text-[var(--amber)]' : 'border-[var(--border)] text-[var(--muted)]'}`}>
          <KeyRound size={12} /> 인증
        </button>
        <button onClick={() => setVerdictOnly((v) => !v)}
                className={`rounded-lg border px-2 py-1.5 text-xs ${verdictOnly ? 'border-[var(--red)] text-[var(--red)]' : 'border-[var(--border)] text-[var(--muted)]'}`}>
          판정
        </button>
      </div>

      {!targets || all.length === 0 ? (
        <Empty icon={Network}>아직 캡처된 엔드포인트가 없습니다. 프록시(:8080) 경유로 트래픽을 흘리면 채워집니다.</Empty>
      ) : filtered.length === 0 ? (
        <Empty icon={Search}>필터에 맞는 엔드포인트가 없습니다.</Empty>
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
                              className="flex w-full items-center gap-2 px-3 py-2.5 text-left hover:bg-[var(--panel-2)]">
                        <ChevronRight size={13} className={`shrink-0 text-[var(--muted)] transition-transform ${isOpen ? 'rotate-90' : ''}`} />
                        {(t.methods ?? []).map((m) => (
                          <span key={m} className="rounded px-1.5 py-0.5 text-[10px] font-bold"
                                style={{ color: 'var(--accent)', background: 'color-mix(in srgb, var(--accent) 14%, transparent)' }}>{m}</span>
                        ))}
                        <span className="font-mono text-sm">{t.path}</span>
                        {t.auth_required && <KeyRound size={12} className="text-[var(--amber)]" />}
                        {t.verdict && <Badge text={t.verdict} color="var(--red)" />}
                        {t.params && t.params.length > 0 && (
                          <span className="text-[10px] text-[var(--muted)]">· {t.params.length}p</span>
                        )}
                        {typeof t.count === 'number' && t.count > 0 && (
                          <span className="ml-auto shrink-0 text-[11px] text-[var(--muted)]">{t.count} hits</span>
                        )}
                      </button>
                      {isOpen && (
                        <div className="border-t border-[var(--border)] bg-[var(--panel-2)] px-3 py-2.5 pl-8 text-xs">
                          <div className="mb-2 flex flex-wrap gap-x-5 gap-y-1 text-[var(--muted)]">
                            <span>히트 <b className="text-[var(--text)]">{t.count ?? 0}</b></span>
                            <span className="inline-flex items-center gap-1"><Clock size={11} /> 최초 <b className="text-[var(--text)]">{fmtTime(t.first_seen)}</b></span>
                            <span className="inline-flex items-center gap-1"><Clock size={11} /> 최근 <b className="text-[var(--text)]">{fmtTime(t.last_seen)}</b></span>
                            <span>인증 <b className="text-[var(--text)]">{t.auth_required ? '필요' : '—'}</b></span>
                          </div>
                          {t.verdict && <div className="mb-2 text-[var(--muted)]">판정: <span className="text-[var(--text)]">{t.verdict}</span></div>}
                          {t.params && t.params.length > 0 ? (
                            <div className="overflow-x-auto">
                              <table className="w-full border-collapse text-[11px]">
                                <thead>
                                  <tr className="text-left text-[var(--muted)]">
                                    <th className="py-1 pr-3 font-medium">위치</th>
                                    <th className="py-1 pr-3 font-medium">이름</th>
                                    <th className="py-1 pr-3 font-medium">타입</th>
                                    <th className="py-1 pr-3 font-medium">필수</th>
                                    <th className="py-1 font-medium">샘플</th>
                                  </tr>
                                </thead>
                                <tbody className="font-mono">
                                  {t.params.map((p) => (
                                    <tr key={p.in + p.name} className="border-t border-[var(--border)]">
                                      <td className="py-1 pr-3 text-[var(--muted)]">{p.in}</td>
                                      <td className="py-1 pr-3">{p.name}</td>
                                      <td className="py-1 pr-3 text-[var(--muted)]">{p.type ?? '—'}</td>
                                      <td className="py-1 pr-3">{p.required ? <span className="text-[var(--red)]">필수</span> : '—'}</td>
                                      <td className="py-1 text-[var(--muted)]">{p.sample ?? '—'}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          ) : <div className="text-[var(--muted)]">파라미터 없음</div>}
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

export function Recon() {
  const { data: targets } = usePoll<Target[]>('/api/endpoints', 4000)
  const { data: rules } = usePoll<Rule[]>('/api/rules', 8000)
  const { data: stats } = usePoll<Stats>('/api/stats', 5000)
  const { data: auth } = usePoll<AuthSummary>('/api/auth', 8000)

  return (
    <div className="grid gap-5 lg:grid-cols-[2fr_1fr]">
      {/* 엔드포인트 트리 (FR-2.4) */}
      <div className="space-y-5">
        <CrawlExplore />
        <EndpointTree targets={targets} />
      </div>

      {/* 우측: 파이프라인·스코프·인증 */}
      <div className="space-y-5">
        {/* 판단 파이프라인 (FR-2.2) */}
        <Card title="Judgment Pipeline" icon={Filter}>
          <div className="mb-3 flex items-center gap-2 text-xs">
            <Stage label="Scope" sub="hard" />
            <Arrow />
            <Stage label="Rule" sub={`${rules?.length ?? 0} rules`} />
            <Arrow />
            <Stage label="LLM" sub={stats?.llm_provider ?? '—'} />
            <Arrow />
            <Stage label="Forward" sub="capture" />
          </div>
          <div className="space-y-1">
            {(rules ?? []).map((r, i) => (
              <div key={i} className="flex items-center gap-2 rounded-lg px-2 py-1.5 text-xs hover:bg-[var(--panel-2)]">
                <Badge text={r.action} color={r.action === 'block' ? 'var(--red)' : 'var(--green)'} />
                <span className="font-mono text-[var(--muted)]">{(r.methods ?? []).join('/') || '*'}</span>
                <span className="font-mono truncate flex-1">{r.path_pattern || '*'}</span>
              </div>
            ))}
            {(!rules || rules.length === 0) && <Empty>기본 룰셋 없음</Empty>}
          </div>
        </Card>

        {/* 스코프 (FR-2.1) */}
        <Card title="Scope (whitelist)" icon={Globe}>
          <div className="flex flex-wrap gap-1.5">
            {(stats?.scope ?? []).map((s) => (
              <span key={s} className="rounded-md border border-[var(--border)] px-2 py-0.5 font-mono text-xs">{s}</span>
            ))}
          </div>
        </Card>

        {/* 인증·신원 (FR-2.5 / FR-3.6) */}
        <Card title="Auth & Identities" icon={KeyRound}>
          <div className="flex items-center justify-between text-sm">
            <span className="text-[var(--muted)]">Session injection</span>
            <Dot text={auth?.enabled ? 'Enabled' : 'Off'} color={auth?.enabled ? 'var(--green)' : 'var(--muted)'} />
          </div>
          {auth && (auth.cookies?.length || auth.headers?.length) ? (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {(auth.cookies ?? []).map((c) => <Badge key={c} text={`cookie:${c}`} color="var(--blue)" />)}
              {(auth.headers ?? []).map((h) => <Badge key={h} text={`hdr:${h}`} color="var(--blue)" />)}
            </div>
          ) : null}
          <div className="mt-3 border-t border-[var(--border)] pt-2.5">
            <div className="eyebrow mb-1.5 flex items-center gap-1.5"><ShieldCheck size={12} /> 진단 신원</div>
            {auth?.identities?.length ? (
              <div className="space-y-1">
                {auth.identities.map((id) => (
                  <div key={id.name} className="flex items-center justify-between text-sm">
                    <span className="font-medium">{id.name}</span>
                    <span className="text-xs text-[var(--muted)]">{id.cookies.length + id.headers.length} creds</span>
                  </div>
                ))}
              </div>
            ) : <div className="text-xs text-[var(--muted)]">등록된 신원 없음 (anon만)</div>}
          </div>
        </Card>

        <LoginSeqCard />
      </div>
    </div>
  )
}

// LoginSeqCard — 세션 지속성(FR-2.5): 만료 시 자동 재로그인 절차 설정. 값은 마스킹, 저장은 리더 전용.
function LoginSeqCard() {
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
      setMsg('저장됨 — 세션 만료 시 자동 재로그인됩니다.'); setOpen(false)
    } catch (e) { setErr(String(e)) } finally { setBusy(false) }
  }

  const inp = 'w-full rounded-lg border border-[var(--border)] bg-[var(--panel-2)] px-2 py-1 text-xs'

  return (
    <Card title="로그인 시퀀스 (세션 지속성)" icon={KeyRound}
          right={<Dot text={info?.enabled ? 'Enabled' : 'Off'} color={info?.enabled ? 'var(--green)' : 'var(--muted)'} />}>
      <p className="mb-2 text-[11px] text-[var(--muted)]">
        긴 스캔 중 세션이 만료되면 이 절차로 자동 재로그인합니다. <b className="text-[var(--text)]">만료 표식(정규식)</b>이 있어야 활성화됩니다.
      </p>
      {!open ? (
        <div className="space-y-1.5 text-xs">
          {info?.url ? (
            <>
              <Row2 k="URL" v={info.url} />
              <Row2 k="만료 표식" v={info.logged_out || '—'} />
              <Row2 k="필드" v={info.fields.join(', ') || '—'} />
              {info.token_field && <Row2 k="CSRF 토큰" v={info.token_field} />}
            </>
          ) : <div className="text-[var(--muted)]">설정되지 않음</div>}
          <button onClick={edit} className="mt-1 rounded-lg border border-[var(--border)] px-2.5 py-1 text-xs font-semibold">
            {info?.url ? '수정' : '설정'}
          </button>
          {msg && <div className="text-[11px]" style={{ color: 'var(--green)' }}>{msg}</div>}
        </div>
      ) : (
        <div className="space-y-2">
          <label className="block"><span className="eyebrow">로그인 URL</span>
            <input className={inp} value={url} onChange={(e) => setUrl(e.target.value)} placeholder="http://target/login.php" /></label>
          <label className="block"><span className="eyebrow">만료 표식 (정규식)</span>
            <input className={inp} value={loggedOut} onChange={(e) => setLoggedOut(e.target.value)} placeholder="(?i)login\.php|please log in" /></label>
          <div>
            <span className="eyebrow">폼 필드 (값은 저장 시에만 전송)</span>
            {rows.map((r, i) => (
              <div key={i} className="mt-1 flex gap-1">
                <input className={inp + ' w-1/3'} value={r.k} placeholder="name"
                       onChange={(e) => setRows(rows.map((x, j) => j === i ? { ...x, k: e.target.value } : x))} />
                <input className={inp} type={/pass|pw|secret/i.test(r.k) ? 'password' : 'text'} value={r.v} placeholder="value" autoComplete="off"
                       onChange={(e) => setRows(rows.map((x, j) => j === i ? { ...x, v: e.target.value } : x))} />
                <button className="px-1 text-[var(--muted)]" onClick={() => setRows(rows.filter((_, j) => j !== i))}>✕</button>
              </div>
            ))}
            <button className="mt-1 text-[11px] text-[var(--muted)] underline" onClick={() => setRows([...rows, { k: '', v: '' }])}>+ 필드 추가</button>
          </div>
          <details className="text-xs">
            <summary className="cursor-pointer text-[var(--muted)]">CSRF 토큰 (선택)</summary>
            <label className="mt-1 block"><span className="eyebrow">토큰 취득 URL</span>
              <input className={inp} value={tokenURL} onChange={(e) => setTokenURL(e.target.value)} placeholder="http://target/login.php" /></label>
            <label className="mt-1 block"><span className="eyebrow">토큰 input name</span>
              <input className={inp} value={tokenField} onChange={(e) => setTokenField(e.target.value)} placeholder="user_token" /></label>
          </details>
          <div className="flex items-center gap-2">
            <button onClick={save} disabled={busy || !url || !loggedOut}
                    className="rounded-lg px-3 py-1.5 text-xs font-semibold disabled:opacity-50"
                    style={{ background: 'var(--accent)', color: 'var(--accent-fg)' }}>{busy ? '저장 중…' : '저장'}</button>
            <button onClick={() => setOpen(false)} className="text-xs text-[var(--muted)]">취소</button>
          </div>
          {err && <div className="text-[11px]" style={{ color: 'var(--red)' }}>저장 실패: {err}</div>}
          <p className="text-[10px] text-[var(--muted)]">저장은 리더 전용. 비밀번호는 응답에 표시되지 않으며 인메모리 주입기에만 반영됩니다.</p>
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

function Stage({ label, sub }: { label: string; sub: string }) {
  return (
    <div className="flex-1 rounded-lg border border-[var(--border)] bg-[var(--panel-2)] px-2 py-1.5 text-center">
      <div className="text-[11px] font-semibold">{label}</div>
      <div className="text-[9px] text-[var(--muted)]">{sub}</div>
    </div>
  )
}
function Arrow() { return <span className="text-[var(--muted)]">→</span> }
