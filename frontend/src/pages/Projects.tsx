import { useRef, useState } from 'react'
import { FolderKanban, Plus, Check, Power, Globe, Lock, KeyRound, Save, ShieldCheck, Download, Upload, Users, X, Server, Radio, Trash2, RotateCcw, AlertTriangle } from 'lucide-react'
import { usePoll, apiPost, type Project, type Me, type CredSummary, type Finding, type User, type TenantInfo } from '../api'
import { Card, Badge, Empty } from '../components/ui'

const SCHEMES = ['주요정보통신기반시설', '전자금융', '모바일']

export function Projects() {
  const { data, error } = usePoll<Project[]>('/api/projects', 4000)
  const { data: trash } = usePoll<Project[]>('/api/projects/trash', 4000)
  const { data: active } = usePoll<Project>('/api/active-project', 4000)
  const { data: me } = usePoll<Me>('/api/me', 5000)
  const { data: extInfo } = usePoll<{ ext: string }>('/api/artifact-ext', 30000)
  const [busy, setBusy] = useState('')
  const [showNew, setShowNew] = useState(false)
  const [tab, setTab] = useState<'active' | 'trash'>('active')
  const [confirm, setConfirm] = useState<{ kind: 'delete' | 'purge'; project: Project } | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  const canCreate = me?.can.includes('project:create') ?? false
  const canDelete = me?.can.includes('project:delete') ?? false
  const ext = extInfo?.ext ?? '.cgpkg'

  async function importFile(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0]
    if (!f) return
    const buf = await f.arrayBuffer()
    await fetch('/api/import-bundle', { method: 'POST', body: buf })
    if (fileRef.current) fileRef.current.value = ''
  }

  async function activate(id: string) {
    setBusy(id)
    try { await apiPost('/api/activate-project', { id }) } finally { setBusy('') }
  }
  async function softDelete(id: string) {
    setBusy(id)
    try { await apiPost(`/api/projects/${id}/delete`, {}) }
    catch (e) { alert('삭제 실패: ' + e) } finally { setBusy(''); setConfirm(null) }
  }
  async function restore(id: string) {
    setBusy(id)
    try { await apiPost(`/api/projects/${id}/restore`, {}) }
    catch (e) { alert('복구 실패: ' + e) } finally { setBusy('') }
  }
  async function purge(id: string) {
    setBusy(id)
    try { await apiPost(`/api/projects/${id}/purge`, {}) }
    catch (e) { alert('영구삭제 실패: ' + e) } finally { setBusy(''); setConfirm(null) }
  }

  const projects = data ?? []
  const trashed = trash ?? []

  return (
    <div className="space-y-5">
      <Card
        title="Projects"
        icon={FolderKanban}
        right={
          <div className="flex items-center gap-2">
            {canCreate && (
              <>
                <input ref={fileRef} type="file" accept={ext} onChange={importFile} className="hidden" />
                <button onClick={() => fileRef.current?.click()}
                        className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border)] bg-[var(--panel-2)] px-3 py-1.5 text-xs font-medium hover:opacity-80"
                        title={`프로젝트 파일(${ext}) 가져오기`}>
                  <Upload size={13} /> Import
                </button>
                <button onClick={() => setShowNew((s) => !s)}
                        className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold"
                        style={{ background: 'var(--accent)', color: 'var(--accent-fg)' }}>
                  <Plus size={14} /> New Project
                </button>
              </>
            )}
            {!canCreate && (
              <span className="inline-flex items-center gap-1.5 text-xs text-[var(--muted)]" title="리더만 생성/가져오기 가능">
                <Lock size={12} /> 리더만
              </span>
            )}
          </div>
        }
      >
        {showNew && canCreate && <NewProjectForm onDone={() => setShowNew(false)} />}

        {/* 활성 | 휴지통 탭 */}
        <div className="mb-3 flex gap-1 border-b border-[var(--border)]">
          <TabBtn on={tab === 'active'} onClick={() => setTab('active')}>활성 ({projects.length})</TabBtn>
          <TabBtn on={tab === 'trash'} onClick={() => setTab('trash')}>
            <span className="inline-flex items-center gap-1"><Trash2 size={12} /> 휴지통 ({trashed.length})</span>
          </TabBtn>
        </div>

        {tab === 'active' ? (
          error ? (
            <Empty>불러오기 실패: {error}</Empty>
          ) : projects.length === 0 ? (
            <Empty icon={FolderKanban}>프로젝트가 없습니다.</Empty>
          ) : (
            <div className="space-y-2">
              {projects.map((p) => {
                const isActive = active?.id === p.id
                return (
                  <div key={p.id}
                       className="rounded-lg border p-3"
                       style={{ borderColor: isActive ? 'var(--accent)' : 'var(--border)',
                                background: isActive ? 'color-mix(in srgb, var(--accent) 8%, transparent)' : 'var(--panel-2)' }}>
                    <div className="flex items-center gap-4">
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="font-semibold">{p.name}</span>
                          <span className="rounded border border-[var(--border)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--muted)]">{p.id}</span>
                          {isActive && <Badge text="active" color="var(--green)" dot />}
                          <ProjectFindings id={p.id} />
                        </div>
                        <div className="mt-0.5 flex items-center gap-1.5 font-mono text-xs text-[var(--muted)]">
                          <Globe size={11} /> {p.main_url}
                        </div>
                        <div className="mt-1 flex flex-wrap gap-1">
                          {(p.scope ?? []).map((s) => <span key={s} className="rounded bg-[var(--panel)] px-1.5 py-0.5 font-mono text-[10px]">{s}</span>)}
                          {(p.schemes ?? []).map((s) => <Badge key={s} text={s} color="var(--accent)" />)}
                        </div>
                      </div>
                      <div className="text-right text-[10px] text-[var(--muted)]">created<br />{p.created}</div>
                      <a href={`/api/projects/${p.id}/bundle`}
                         className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 py-1.5 text-xs font-medium hover:opacity-80"
                         title={`프로젝트 파일(${ext})로 내보내기 — DRM 비간섭`}>
                        <Download size={13} /> {ext}
                      </a>
                      {isActive ? (
                        <span className="inline-flex items-center gap-1 text-xs font-medium" style={{ color: 'var(--green)' }}>
                          <Check size={14} /> 활성
                        </span>
                      ) : (
                        <button onClick={() => activate(p.id)} disabled={busy === p.id}
                                title="이 프로젝트로 전환 (공유 프록시 :8080·화면 기준)"
                                className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 py-1.5 text-xs font-medium hover:opacity-80 disabled:opacity-50">
                          <Power size={13} /> {busy === p.id ? '…' : 'Activate'}
                        </button>
                      )}
                      {canDelete && (
                        <button onClick={() => setConfirm({ kind: 'delete', project: p })} disabled={isActive || busy === p.id}
                                title={isActive ? '활성 프로젝트는 삭제 불가 — 먼저 다른 프로젝트로 전환' : '삭제 (휴지통으로 이동)'}
                                className="inline-flex items-center rounded-lg border border-[var(--border)] bg-[var(--panel)] px-2 py-1.5 text-[var(--muted)] hover:text-[var(--red)] hover:border-[var(--red)] disabled:opacity-30 disabled:hover:text-[var(--muted)] disabled:hover:border-[var(--border)]">
                          <Trash2 size={13} />
                        </button>
                      )}
                    </div>
                    <TenantSection projectId={p.id} />
                    <MembersSection project={p} canManage={me?.can.includes('project:members') ?? false} />
                    <CredentialsSection projectId={p.id} canEdit={canCreate} />
                  </div>
                )
              })}
            </div>
          )
        ) : (
          // 휴지통 탭
          trashed.length === 0 ? (
            <Empty icon={Trash2}>휴지통이 비어 있습니다.</Empty>
          ) : (
            <div className="space-y-2">
              {trashed.map((p) => (
                <div key={p.id} className="rounded-lg border border-[var(--border)] bg-[var(--panel-2)] p-3">
                  <div className="flex items-center gap-4">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold">{p.name}</span>
                        <span className="rounded border border-[var(--border)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--muted)]">{p.id}</span>
                        <Badge text="휴지통" color="var(--muted)" />
                      </div>
                      <div className="mt-0.5 flex items-center gap-1.5 font-mono text-xs text-[var(--muted)]">
                        <Globe size={11} /> {p.main_url}
                      </div>
                      <div className="mt-0.5 text-[10px] text-[var(--muted)]">삭제됨: {fmtTime(p.deleted_at)}</div>
                    </div>
                    {canDelete ? (
                      <>
                        <button onClick={() => restore(p.id)} disabled={busy === p.id}
                                title="복구 (활성 목록으로 되돌림)"
                                className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 py-1.5 text-xs font-medium hover:opacity-80 disabled:opacity-50">
                          <RotateCcw size={13} /> {busy === p.id ? '…' : '복구'}
                        </button>
                        <button onClick={() => setConfirm({ kind: 'purge', project: p })} disabled={busy === p.id}
                                title="즉시 영구삭제 (findings·scanruns 포함, 복구 불가)"
                                className="inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium disabled:opacity-50"
                                style={{ borderColor: 'var(--red)', color: 'var(--red)' }}>
                          <Trash2 size={13} /> 영구삭제
                        </button>
                      </>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-[10px] text-[var(--muted)]"><Lock size={10} /> 리더만</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )
        )}
      </Card>
      <p className="text-xs text-[var(--muted)]">
        활성 프로젝트를 전환하면 진단 대상 범위와 점검 항목이 그 프로젝트로 바뀌고,
        취약점·커버리지·리포트·이행점검이 해당 프로젝트 기준으로 표시됩니다.
        삭제한 프로젝트는 휴지통으로 이동하며 언제든 복구할 수 있습니다.
      </p>

      {confirm && (
        <ConfirmModal
          kind={confirm.kind}
          project={confirm.project}
          busy={busy === confirm.project.id}
          onCancel={() => setConfirm(null)}
          onConfirm={() => (confirm.kind === 'delete' ? softDelete(confirm.project.id) : purge(confirm.project.id))}
        />
      )}
    </div>
  )
}

// TabBtn — 활성/휴지통 탭 버튼.
function TabBtn({ on, onClick, children }: { on: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button onClick={onClick}
            className="-mb-px border-b-2 px-3 py-1.5 text-xs font-semibold"
            style={{ borderColor: on ? 'var(--accent)' : 'transparent', color: on ? 'var(--text)' : 'var(--muted)' }}>
      {children}
    </button>
  )
}

// ConfirmModal — 삭제/영구삭제 확인 안내창(이슈 #14).
function ConfirmModal({ kind, project, busy, onCancel, onConfirm }:
  { kind: 'delete' | 'purge'; project: Project; busy: boolean; onCancel: () => void; onConfirm: () => void }) {
  const danger = kind === 'purge'
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4" onClick={onCancel}>
      <div className="w-full max-w-md rounded-xl border border-[var(--border)] bg-[var(--panel)] p-5 shadow-[var(--shadow)]"
           onClick={(e) => e.stopPropagation()}>
        <div className="mb-2 flex items-center gap-2">
          <AlertTriangle size={18} style={{ color: danger ? 'var(--red)' : 'var(--amber)' }} />
          <h3 className="text-sm font-bold">{danger ? '프로젝트 영구삭제' : '프로젝트 삭제'}</h3>
        </div>
        <p className="mb-2 text-sm"><b>{project.name}</b>
          <span className="ml-1.5 font-mono text-xs text-[var(--muted)]">({project.id})</span></p>
        {danger ? (
          <p className="mb-4 text-xs leading-relaxed text-[var(--muted)]">
            이 프로젝트와 <b className="text-[var(--text)]">findings·scanruns가 완전히 삭제</b>되며
            <b className="text-[var(--text)]"> 복구할 수 없습니다.</b> 계속할까요?
          </p>
        ) : (
          <p className="mb-4 text-xs leading-relaxed text-[var(--muted)]">
            삭제하면 <b className="text-[var(--text)]">휴지통으로 이동</b>하며 <b className="text-[var(--text)]">언제든 복구</b>할 수 있습니다.
            (findings·scanruns는 보존됩니다.)
          </p>
        )}
        <div className="flex justify-end gap-2">
          <button onClick={onCancel} className="rounded-lg border border-[var(--border)] px-3 py-1.5 text-xs font-medium">취소</button>
          <button onClick={onConfirm} disabled={busy}
                  className="rounded-lg px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-50"
                  style={{ background: 'var(--red)' }}>
            {busy ? '처리 중…' : danger ? '영구삭제' : '삭제'}
          </button>
        </div>
      </div>
    </div>
  )
}

// fmtTime — RFC3339 시각을 로캘 표기로.
function fmtTime(s?: string) {
  if (!s) return '—'
  const d = new Date(s)
  return isNaN(d.getTime()) ? s : d.toLocaleString()
}

// TenantSection — 프록시 멀티테넌시 (§5.1 FR-1.1). 프로젝트 전용 프록시 포트 시작/중지.
function TenantSection({ projectId }: { projectId: string }) {
  const { data: tenants } = usePoll<TenantInfo[]>('/api/tenants', 3000)
  const [busy, setBusy] = useState(false)
  const [justStarted, setJustStarted] = useState<TenantInfo | null>(null)
  // 폴링 결과 우선, 없으면 방금 시작한 응답(즉시 반영 — 폴링 지연 체감 제거).
  const t = tenants?.find((x) => x.project_id === projectId) ?? justStarted

  async function start() {
    setBusy(true)
    try { setJustStarted(await apiPost<TenantInfo>(`/api/tenants/${projectId}/start`, {})) } finally { setBusy(false) }
  }
  async function stop() {
    setBusy(true)
    try { await apiPost(`/api/tenants/${projectId}/stop`, {}); setJustStarted(null) } finally { setBusy(false) }
  }

  return (
    <div className="mt-2.5 border-t border-[var(--border)] pt-2.5">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="inline-flex items-center gap-1 text-[var(--muted)]"><Server size={12} /> 전용 프록시</span>
        {t ? (
          <>
            <span className="inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 font-medium"
                  style={{ color: 'var(--green)', background: 'color-mix(in srgb, var(--green) 14%, transparent)' }}>
              <Radio size={11} /> 실행 중 · 127.0.0.1:{t.port}
            </span>
            <span className="text-[10px] text-[var(--muted)]">요청 {t.traffic ?? 0}건 · 캡처 {t.endpoints}개 · 격리됨</span>
            <span className="text-[10px] text-[var(--muted)]">이 포트로 프록시 설정해 진단</span>
            <button onClick={stop} disabled={busy}
                    className="rounded-lg border border-[var(--border)] bg-[var(--panel)] px-2.5 py-1 text-[11px] font-medium hover:opacity-80 disabled:opacity-50">
              중지
            </button>
          </>
        ) : (
          <>
            <span className="text-[10px] text-[var(--muted)]" title="전용 프록시 미실행 시 활성 프로젝트가 공유 :8080 사용">미실행 (공유 프록시 사용)</span>
            <button onClick={start} disabled={busy}
                    title="이 프로젝트 전용 프록시를 별도 포트에 (동시 진단·격리)"
                    className="inline-flex items-center gap-1 rounded-lg px-2.5 py-1 text-[11px] font-semibold disabled:opacity-50"
                    style={{ background: 'var(--accent)', color: 'var(--accent-fg)' }}>
              <Power size={11} /> {busy ? '시작 중…' : '전용 프록시 시작'}
            </button>
          </>
        )}
      </div>
    </div>
  )
}

// MembersSection — 프로젝트별 멤버 ACL (§5.1 FR-1.4). 소유자+멤버 표시 + 리더 추가/제거.
function MembersSection({ project, canManage }: { project: Project; canManage: boolean }) {
  const { data: users } = usePoll<User[]>('/api/users', 10000)
  const nameOf = (id: string) => users?.find((u) => u.id === id)?.name ?? id
  const members = project.members ?? []
  const nonMembers = (users ?? []).filter((u) => u.id !== project.owner && !members.includes(u.id))

  async function add(uid: string) { if (uid) await apiPost(`/api/projects/${project.id}/members`, { user_id: uid }) }
  async function remove(uid: string) { await apiPost(`/api/projects/${project.id}/members/remove`, { user_id: uid }) }

  return (
    <div className="mt-2.5 border-t border-[var(--border)] pt-2.5">
      <div className="flex flex-wrap items-center gap-1.5 text-xs">
        <span className="inline-flex items-center gap-1 text-[var(--muted)]"><Users size={12} /> 멤버</span>
        {project.owner && <Badge text={`${nameOf(project.owner)} (owner)`} color="var(--accent)" />}
        {members.map((m) => (
          <span key={m} className="inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs font-medium"
                style={{ color: 'var(--blue)', background: 'color-mix(in srgb, var(--blue) 14%, transparent)' }}>
            {nameOf(m)}
            {canManage && <button onClick={() => remove(m)} className="hover:opacity-70" title="제거"><X size={11} /></button>}
          </span>
        ))}
        {members.length === 0 && <span className="text-[10px] text-[var(--muted)]">추가 멤버 없음</span>}
        {canManage && nonMembers.length > 0 && (
          <select defaultValue="" onChange={(e) => { add(e.target.value); e.target.value = '' }}
                  className="rounded border border-[var(--border)] bg-[var(--panel-2)] px-1 py-0.5 text-[10px]">
            <option value="">+ 멤버 추가</option>
            {nonMembers.map((u) => <option key={u.id} value={u.id}>{u.name} ({u.role})</option>)}
          </select>
        )}
        {!canManage && <span className="inline-flex items-center gap-1 text-[10px] text-[var(--muted)]"><Lock size={10} /> 리더만 관리</span>}
      </div>
    </div>
  )
}

// ProjectFindings — RESTful 리소스로 프로젝트별 finding 수 표시 (§5.1 FR-1.1). 활성 전환 불필요.
function ProjectFindings({ id }: { id: string }) {
  const { data } = usePoll<Finding[]>(`/api/projects/${id}/findings`, 6000)
  if (!data || data.length === 0) return null
  return <Badge text={`${data.length} findings`} color="var(--red)" />
}

// CredentialsSection — 프로젝트 인증정보 (§5.1 FR-1.4). 마스킹 요약 + 리더 설정폼(암호화 저장).
function CredentialsSection({ projectId, canEdit }: { projectId: string; canEdit: boolean }) {
  const { data: sum } = usePoll<CredSummary>(`/api/project-credentials?id=${projectId}`, 6000)
  const [editing, setEditing] = useState(false)
  const [cookies, setCookies] = useState('')
  const [headers, setHeaders] = useState('')
  const [busy, setBusy] = useState(false)

  function parse(text: string): Record<string, string> {
    const out: Record<string, string> = {}
    for (const line of text.split('\n')) {
      const i = line.indexOf('=')
      if (i > 0) out[line.slice(0, i).trim()] = line.slice(i + 1).trim()
    }
    return out
  }
  async function save() {
    setBusy(true)
    try {
      await apiPost(`/api/project-credentials?id=${projectId}`, {
        cookies: parse(cookies), headers: parse(headers),
      })
      setEditing(false); setCookies(''); setHeaders('')
    } finally { setBusy(false) }
  }

  return (
    <div className="mt-2.5 border-t border-[var(--border)] pt-2.5">
      <div className="flex items-center justify-between">
        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          <span className="inline-flex items-center gap-1 text-[var(--muted)]"><KeyRound size={12} /> 인증정보</span>
          {sum?.has_creds ? (
            <>
              <ShieldCheck size={12} style={{ color: 'var(--green)' }} />
              <span className="text-[10px] text-[var(--muted)]">암호화됨</span>
              {(sum.cookies ?? []).map((c) => <Badge key={c} text={`cookie:${c}`} color="var(--blue)" />)}
              {(sum.headers ?? []).map((h) => <Badge key={h} text={`hdr:${h}`} color="var(--blue)" />)}
              {(sum.identities ?? []).map((i) => <Badge key={i} text={`id:${i}`} color="var(--accent)" />)}
            </>
          ) : (
            <span className="text-[10px] text-[var(--muted)]">설정 안 됨</span>
          )}
        </div>
        {canEdit ? (
          <button onClick={() => setEditing((e) => !e)} className="text-[11px] font-medium text-[var(--accent)] hover:opacity-80">
            {editing ? '취소' : sum?.has_creds ? '변경' : '설정'}
          </button>
        ) : (
          <span className="inline-flex items-center gap-1 text-[10px] text-[var(--muted)]"><Lock size={10} /> 리더만</span>
        )}
      </div>

      {editing && canEdit && (
        <div className="mt-2 grid gap-2 sm:grid-cols-2">
          <label className="block">
            <span className="eyebrow">Cookies (name=value, 줄당 하나)</span>
            <textarea className="mt-1 h-16 w-full rounded-lg border border-[var(--border)] bg-[var(--panel)] px-2 py-1.5 font-mono text-xs"
                      value={cookies} onChange={(e) => setCookies(e.target.value)} placeholder="SESSIONID=abc123" />
          </label>
          <label className="block">
            <span className="eyebrow">Headers (name=value, 줄당 하나)</span>
            <textarea className="mt-1 h-16 w-full rounded-lg border border-[var(--border)] bg-[var(--panel)] px-2 py-1.5 font-mono text-xs"
                      value={headers} onChange={(e) => setHeaders(e.target.value)} placeholder="Authorization=Bearer xyz" />
          </label>
          <div className="sm:col-span-2 flex items-center justify-between">
            <span className="text-[10px] text-[var(--muted)]">AES-256-GCM 로 서버에 암호화 저장 — 평문은 저장/전송되지 않음</span>
            <button onClick={save} disabled={busy}
                    className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold disabled:opacity-50"
                    style={{ background: 'var(--accent)', color: 'var(--accent-fg)' }}>
              <Save size={13} /> {busy ? '암호화 저장 중…' : '암호화 저장'}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

function NewProjectForm({ onDone }: { onDone: () => void }) {
  const [name, setName] = useState('')
  const [scope, setScope] = useState('')
  const [schemes, setSchemes] = useState<string[]>([])
  const [busy, setBusy] = useState(false)

  async function create() {
    if (!name.trim()) return
    setBusy(true)
    try {
      await apiPost('/api/projects', {
        name: name.trim(),
        scope: scope.split(',').map((s) => s.trim()).filter(Boolean),
        schemes,
      })
      onDone()
    } finally { setBusy(false) }
  }

  const inp = 'w-full rounded-lg border border-[var(--border)] bg-[var(--panel-2)] px-2.5 py-1.5 text-sm'
  return (
    <div className="mb-4 rounded-lg border border-[var(--border)] bg-[var(--panel-2)] p-3">
      <div className="grid gap-2 sm:grid-cols-2">
        <label className="block">
          <span className="eyebrow">대상명 *</span>
          <input className={inp} value={name} onChange={(e) => setName(e.target.value)} placeholder="Financial App v2" />
        </label>
        <label className="block">
          <span className="eyebrow">Scope (쉼표 구분)</span>
          <input className={inp} value={scope} onChange={(e) => setScope(e.target.value)} placeholder="api.example.com, example.com" />
        </label>
      </div>
      <div className="mt-2">
        <span className="eyebrow">선택 스킴</span>
        <div className="mt-1 flex flex-wrap gap-1.5">
          {SCHEMES.map((s) => {
            const on = schemes.includes(s)
            return (
              <button key={s} onClick={() => setSchemes((cur) => on ? cur.filter((x) => x !== s) : [...cur, s])}
                      className="rounded-md px-2 py-1 text-xs font-medium"
                      style={on ? { background: 'var(--accent)', color: 'var(--accent-fg)' }
                                : { border: '1px solid var(--border)', color: 'var(--muted)' }}>
                {s}
              </button>
            )
          })}
        </div>
      </div>
      <div className="mt-3 flex justify-end gap-2">
        <button onClick={onDone} className="rounded-lg border border-[var(--border)] px-3 py-1.5 text-xs font-medium">취소</button>
        <button onClick={create} disabled={busy || !name.trim()}
                className="rounded-lg px-3 py-1.5 text-xs font-semibold disabled:opacity-50"
                style={{ background: 'var(--accent)', color: 'var(--accent-fg)' }}>
          {busy ? '생성 중…' : '생성'}
        </button>
      </div>
    </div>
  )
}
