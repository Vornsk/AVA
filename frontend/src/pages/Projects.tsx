import { useRef, useState } from 'react'
import { FolderKanban, Plus, Check, Power, Globe, Lock, KeyRound, Save, ShieldCheck, Download, Upload, Users, X, Server, Radio, Trash2, RotateCcw, AlertTriangle } from 'lucide-react'
import { usePoll, apiPost, type Project, type Me, type CredSummary, type Finding, type User, type TenantInfo, type Stats } from '../api'
import { Card, Badge, Empty } from '../components/ui'
import { useT } from '../i18n'

// 규제 스킴명 — 백엔드로 전송/저장되는 값이라 번역하지 않는다(도메인 데이터).
const SCHEMES = ['주요정보통신기반시설', '전자금융', '모바일']

export function Projects() {
  const t = useT()
  const { data, error } = usePoll<Project[]>('/api/projects', 4000)
  const { data: trash } = usePoll<Project[]>('/api/projects/trash', 4000)
  const { data: stats } = usePoll<Stats>('/api/stats', 30000)
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
    catch (e) { alert(t('projects.delete') + ': ' + e) } finally { setBusy(''); setConfirm(null) }
  }
  async function restore(id: string) {
    setBusy(id)
    try { await apiPost(`/api/projects/${id}/restore`, {}) }
    catch (e) { alert(t('projects.restore') + ': ' + e) } finally { setBusy('') }
  }
  async function purge(id: string) {
    setBusy(id)
    try { await apiPost(`/api/projects/${id}/purge`, {}) }
    catch (e) { alert(t('projects.purge') + ': ' + e) } finally { setBusy(''); setConfirm(null) }
  }

  const projects = data ?? []
  const trashed = trash ?? []
  const noActive = !!data && !active?.id // 프로젝트는 로드됐는데 활성이 없음(모두 삭제/휴지통)

  // 활성 프로젝트를 지울 때 자동 전환될 대상(백엔드 firstLiveExcept 와 같은 규칙 — List 순서상 첫 타 프로젝트).
  function switchTargetName(target: Project): string | null {
    const next = projects.find((p) => p.id !== target.id)
    return next ? next.name : null
  }

  return (
    <div className="space-y-5">
      {noActive && (
        <div className="flex items-start gap-2 rounded-lg border px-3 py-2.5 text-xs"
             style={{ borderColor: 'var(--amber)', background: 'color-mix(in srgb, var(--amber) 10%, transparent)', color: 'var(--text)' }}>
          <AlertTriangle size={15} style={{ color: 'var(--amber)', flexShrink: 0, marginTop: 1 }} />
          <span>{t('projects.noActiveWarn')}</span>
        </div>
      )}
      <Card
        title={t('projects.title')}
        icon={FolderKanban}
        right={
          <div className="flex items-center gap-2">
            {canCreate && (
              <>
                <input ref={fileRef} type="file" accept={ext} onChange={importFile} className="hidden" />
                <button onClick={() => fileRef.current?.click()}
                        className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border)] bg-[var(--panel-2)] px-3 py-1.5 text-xs font-medium hover:opacity-80"
                        title={t('projects.importTitle', { ext })}>
                  <Upload size={13} /> {t('projects.import')}
                </button>
                <button onClick={() => setShowNew((s) => !s)}
                        className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold"
                        style={{ background: 'var(--accent)', color: 'var(--accent-fg)' }}>
                  <Plus size={14} /> {t('projects.newProject')}
                </button>
              </>
            )}
            {!canCreate && (
              <span className="inline-flex items-center gap-1.5 text-xs text-[var(--muted)]" title={t('projects.leaderOnlyTitle')}>
                <Lock size={12} /> {t('projects.leaderOnly')}
              </span>
            )}
          </div>
        }
      >
        {showNew && canCreate && <NewProjectForm onDone={() => setShowNew(false)} />}

        {/* 활성 | 휴지통 탭 */}
        <div className="mb-3 flex gap-1 border-b border-[var(--border)]">
          <TabBtn on={tab === 'active'} onClick={() => setTab('active')}>{t('projects.tabActive')} ({projects.length})</TabBtn>
          <TabBtn on={tab === 'trash'} onClick={() => setTab('trash')}>
            <span className="inline-flex items-center gap-1"><Trash2 size={12} /> {t('projects.tabTrash')} ({trashed.length})</span>
          </TabBtn>
        </div>

        {tab === 'active' ? (
          error ? (
            <Empty>{t('projects.loadFail')}: {error}</Empty>
          ) : projects.length === 0 ? (
            <Empty icon={FolderKanban}>{t('projects.noProjects')}</Empty>
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
                          {isActive && <Badge text={t('projects.active')} color="var(--green)" dot />}
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
                         title={t('projects.exportTitle', { ext })}>
                        <Download size={13} /> {ext}
                      </a>
                      {isActive ? (
                        <span className="inline-flex items-center gap-1 text-xs font-medium" style={{ color: 'var(--green)' }}>
                          <Check size={14} /> {t('projects.active')}
                        </span>
                      ) : (
                        <button onClick={() => activate(p.id)} disabled={busy === p.id}
                                title={t('projects.switchTitle')}
                                className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 py-1.5 text-xs font-medium hover:opacity-80 disabled:opacity-50">
                          <Power size={13} /> {busy === p.id ? '…' : t('projects.activate')}
                        </button>
                      )}
                      {canDelete && (
                        <button onClick={() => setConfirm({ kind: 'delete', project: p })} disabled={busy === p.id}
                                title={t('projects.delTitle')}
                                className="inline-flex items-center rounded-lg border border-[var(--border)] bg-[var(--panel)] px-2 py-1.5 text-[var(--muted)] hover:text-[var(--red)] hover:border-[var(--red)] disabled:opacity-30">
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
            <Empty icon={Trash2}>{t('projects.trashEmpty')}</Empty>
          ) : (
            <div className="space-y-2">
              {trashed.map((p) => (
                <div key={p.id} className="rounded-lg border border-[var(--border)] bg-[var(--panel-2)] p-3">
                  <div className="flex items-center gap-4">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold">{p.name}</span>
                        <span className="rounded border border-[var(--border)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--muted)]">{p.id}</span>
                        <Badge text={t('projects.trashBadge')} color="var(--muted)" />
                      </div>
                      <div className="mt-0.5 flex items-center gap-1.5 font-mono text-xs text-[var(--muted)]">
                        <Globe size={11} /> {p.main_url}
                      </div>
                      <div className="mt-0.5 text-[10px] text-[var(--muted)]">
                        {t('projects.deletedAt')}: {fmtTime(p.deleted_at)}
                        {daysLeft(p.deleted_at, stats?.retention_days) != null && (
                          <span> · {t('projects.purgeInPre')}<b className="text-[var(--amber)]">{daysLeft(p.deleted_at, stats?.retention_days)}{t('projects.daySuffix')}</b></span>
                        )}
                      </div>
                    </div>
                    {canDelete ? (
                      <>
                        <button onClick={() => restore(p.id)} disabled={busy === p.id}
                                title={t('projects.restoreTitle')}
                                className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 py-1.5 text-xs font-medium hover:opacity-80 disabled:opacity-50">
                          <RotateCcw size={13} /> {busy === p.id ? '…' : t('projects.restore')}
                        </button>
                        <button onClick={() => setConfirm({ kind: 'purge', project: p })} disabled={busy === p.id}
                                title={t('projects.purgeTitle')}
                                className="inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium disabled:opacity-50"
                                style={{ borderColor: 'var(--red)', color: 'var(--red)' }}>
                          <Trash2 size={13} /> {t('projects.purge')}
                        </button>
                      </>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-[10px] text-[var(--muted)]"><Lock size={10} /> {t('projects.leaderOnly')}</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )
        )}
      </Card>
      <p className="text-xs text-[var(--muted)]">
        {t('projects.footer')}
      </p>

      {confirm && (
        <ConfirmModal
          kind={confirm.kind}
          project={confirm.project}
          busy={busy === confirm.project.id}
          activeSwitchNote={
            confirm.kind === 'delete' && active?.id === confirm.project.id
              ? (switchTargetName(confirm.project)
                  ? t('projects.cm.delete.switchTo', { name: switchTargetName(confirm.project) as string })
                  : t('projects.cm.delete.noActive'))
              : undefined
          }
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

// ConfirmModal — 삭제/영구삭제 확인 안내창(이슈 #14). activeSwitchNote 는 활성 프로젝트를
// 삭제할 때 "어디로 자동 전환되는가 / 활성이 없어지는가"를 안내한다(막다른 골목 개선).
function ConfirmModal({ kind, project, busy, activeSwitchNote, onCancel, onConfirm }:
  { kind: 'delete' | 'purge'; project: Project; busy: boolean; activeSwitchNote?: string; onCancel: () => void; onConfirm: () => void }) {
  const t = useT()
  const danger = kind === 'purge'
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4" onClick={onCancel}>
      <div className="w-full max-w-md rounded-xl border border-[var(--border)] bg-[var(--panel)] p-5 shadow-[var(--shadow)]"
           onClick={(e) => e.stopPropagation()}>
        <div className="mb-2 flex items-center gap-2">
          <AlertTriangle size={18} style={{ color: danger ? 'var(--red)' : 'var(--amber)' }} />
          <h3 className="text-sm font-bold">{danger ? t('projects.cm.purgeTitle') : t('projects.cm.deleteTitle')}</h3>
        </div>
        <p className="mb-2 text-sm"><b>{project.name}</b>
          <span className="ml-1.5 font-mono text-xs text-[var(--muted)]">({project.id})</span></p>
        {danger ? (
          <p className="mb-4 text-xs leading-relaxed text-[var(--muted)]">
            {t('projects.cm.purge.pre')}<b className="text-[var(--text)]">{t('projects.cm.purge.b1')}</b>{t('projects.cm.purge.mid')}
            <b className="text-[var(--text)]">{t('projects.cm.purge.b2')}</b>{t('projects.cm.purge.end')}
          </p>
        ) : (
          <div className="mb-4 text-xs leading-relaxed text-[var(--muted)]">
            <p>{t('projects.cm.delete.pre')}<b className="text-[var(--text)]">{t('projects.cm.delete.b1')}</b>{t('projects.cm.delete.mid')}<b className="text-[var(--text)]">{t('projects.cm.delete.b2')}</b>{t('projects.cm.delete.end')}</p>
            {activeSwitchNote && (
              <p className="mt-1.5 inline-flex items-start gap-1" style={{ color: 'var(--amber)' }}>
                <AlertTriangle size={12} style={{ flexShrink: 0, marginTop: 1 }} /> {activeSwitchNote}
              </p>
            )}
          </div>
        )}
        <div className="flex justify-end gap-2">
          <button onClick={onCancel} className="rounded-lg border border-[var(--border)] px-3 py-1.5 text-xs font-medium">{t('common.cancel')}</button>
          <button onClick={onConfirm} disabled={busy}
                  className="rounded-lg px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-50"
                  style={{ background: 'var(--red)' }}>
            {busy ? t('projects.cm.processing') : danger ? t('projects.purge') : t('projects.delete')}
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

// daysLeft — 자동 영구삭제까지 남은 일수 (이슈 #15). deleted_at + retentionDays 기준.
function daysLeft(deletedAt?: string, retentionDays?: number): number | null {
  if (!deletedAt) return null
  const d = new Date(deletedAt)
  if (isNaN(d.getTime())) return null
  const ret = retentionDays ?? 30
  const elapsedDays = (Date.now() - d.getTime()) / 86400000
  return Math.max(0, Math.ceil(ret - elapsedDays))
}

// TenantSection — 프록시 멀티테넌시 (§5.1 FR-1.1). 프로젝트 전용 프록시 포트 시작/중지.
function TenantSection({ projectId }: { projectId: string }) {
  const tr = useT() // 아래 t 는 TenantInfo, 번역 함수는 tr 로 분리
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
        <span className="inline-flex items-center gap-1 text-[var(--muted)]"><Server size={12} /> {tr('projects.tenant.dedicated')}</span>
        {t ? (
          <>
            <span className="inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 font-medium"
                  style={{ color: 'var(--green)', background: 'color-mix(in srgb, var(--green) 14%, transparent)' }}>
              <Radio size={11} /> {tr('projects.tenant.running', { port: t.port })}
            </span>
            <span className="text-[10px] text-[var(--muted)]">{tr('projects.tenant.stats', { traffic: t.traffic ?? 0, endpoints: t.endpoints })}</span>
            <span className="text-[10px] text-[var(--muted)]">{tr('projects.tenant.hint')}</span>
            <button onClick={stop} disabled={busy}
                    className="rounded-lg border border-[var(--border)] bg-[var(--panel)] px-2.5 py-1 text-[11px] font-medium hover:opacity-80 disabled:opacity-50">
              {tr('projects.tenant.stop')}
            </button>
          </>
        ) : (
          <>
            <span className="text-[10px] text-[var(--muted)]" title={tr('projects.tenant.idleTitle')}>{tr('projects.tenant.idle')}</span>
            <button onClick={start} disabled={busy}
                    title={tr('projects.tenant.startTitle')}
                    className="inline-flex items-center gap-1 rounded-lg px-2.5 py-1 text-[11px] font-semibold disabled:opacity-50"
                    style={{ background: 'var(--accent)', color: 'var(--accent-fg)' }}>
              <Power size={11} /> {busy ? tr('projects.tenant.starting') : tr('projects.tenant.start')}
            </button>
          </>
        )}
      </div>
    </div>
  )
}

// MembersSection — 프로젝트별 멤버 ACL (§5.1 FR-1.4). 소유자+멤버 표시 + 리더 추가/제거.
function MembersSection({ project, canManage }: { project: Project; canManage: boolean }) {
  const t = useT()
  const { data: users } = usePoll<User[]>('/api/users', 10000)
  const nameOf = (id: string) => users?.find((u) => u.id === id)?.name ?? id
  const members = project.members ?? []
  const nonMembers = (users ?? []).filter((u) => u.id !== project.owner && !members.includes(u.id))

  async function add(uid: string) { if (uid) await apiPost(`/api/projects/${project.id}/members`, { user_id: uid }) }
  async function remove(uid: string) { await apiPost(`/api/projects/${project.id}/members/remove`, { user_id: uid }) }

  return (
    <div className="mt-2.5 border-t border-[var(--border)] pt-2.5">
      <div className="flex flex-wrap items-center gap-1.5 text-xs">
        <span className="inline-flex items-center gap-1 text-[var(--muted)]"><Users size={12} /> {t('projects.members.label')}</span>
        {project.owner && <Badge text={`${nameOf(project.owner)} (${t('projects.members.owner')})`} color="var(--accent)" />}
        {members.map((m) => (
          <span key={m} className="inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs font-medium"
                style={{ color: 'var(--blue)', background: 'color-mix(in srgb, var(--blue) 14%, transparent)' }}>
            {nameOf(m)}
            {canManage && <button onClick={() => remove(m)} className="hover:opacity-70" title={t('projects.members.remove')}><X size={11} /></button>}
          </span>
        ))}
        {members.length === 0 && <span className="text-[10px] text-[var(--muted)]">{t('projects.members.none')}</span>}
        {canManage && nonMembers.length > 0 && (
          <select defaultValue="" onChange={(e) => { add(e.target.value); e.target.value = '' }}
                  className="rounded border border-[var(--border)] bg-[var(--panel-2)] px-1 py-0.5 text-[10px]">
            <option value="">{t('projects.members.add')}</option>
            {nonMembers.map((u) => <option key={u.id} value={u.id}>{u.name} ({u.role})</option>)}
          </select>
        )}
        {!canManage && <span className="inline-flex items-center gap-1 text-[10px] text-[var(--muted)]"><Lock size={10} /> {t('projects.members.leaderOnly')}</span>}
      </div>
    </div>
  )
}

// ProjectFindings — RESTful 리소스로 프로젝트별 finding 수 표시 (§5.1 FR-1.1). 활성 전환 불필요.
function ProjectFindings({ id }: { id: string }) {
  const t = useT()
  const { data } = usePoll<Finding[]>(`/api/projects/${id}/findings`, 6000)
  if (!data || data.length === 0) return null
  return <Badge text={t('projects.findingsBadge', { n: data.length })} color="var(--red)" />
}

// CredentialsSection — 프로젝트 인증정보 (§5.1 FR-1.4). 마스킹 요약 + 리더 설정폼(암호화 저장).
function CredentialsSection({ projectId, canEdit }: { projectId: string; canEdit: boolean }) {
  const t = useT()
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
          <span className="inline-flex items-center gap-1 text-[var(--muted)]"><KeyRound size={12} /> {t('projects.creds.label')}</span>
          {sum?.has_creds ? (
            <>
              <ShieldCheck size={12} style={{ color: 'var(--green)' }} />
              <span className="text-[10px] text-[var(--muted)]">{t('projects.creds.encrypted')}</span>
              {(sum.cookies ?? []).map((c) => <Badge key={c} text={`cookie:${c}`} color="var(--blue)" />)}
              {(sum.headers ?? []).map((h) => <Badge key={h} text={`hdr:${h}`} color="var(--blue)" />)}
              {(sum.identities ?? []).map((i) => <Badge key={i} text={`id:${i}`} color="var(--accent)" />)}
            </>
          ) : (
            <span className="text-[10px] text-[var(--muted)]">{t('projects.creds.notSet')}</span>
          )}
        </div>
        {canEdit ? (
          <button onClick={() => setEditing((e) => !e)} className="text-[11px] font-medium text-[var(--accent)] hover:opacity-80">
            {editing ? t('common.cancel') : sum?.has_creds ? t('projects.creds.change') : t('projects.creds.setup')}
          </button>
        ) : (
          <span className="inline-flex items-center gap-1 text-[10px] text-[var(--muted)]"><Lock size={10} /> {t('projects.leaderOnly')}</span>
        )}
      </div>

      {editing && canEdit && (
        <div className="mt-2 grid gap-2 sm:grid-cols-2">
          <label className="block">
            <span className="eyebrow">{t('projects.creds.cookies')}</span>
            <textarea className="mt-1 h-16 w-full rounded-lg border border-[var(--border)] bg-[var(--panel)] px-2 py-1.5 font-mono text-xs"
                      value={cookies} onChange={(e) => setCookies(e.target.value)} placeholder="SESSIONID=abc123" />
          </label>
          <label className="block">
            <span className="eyebrow">{t('projects.creds.headers')}</span>
            <textarea className="mt-1 h-16 w-full rounded-lg border border-[var(--border)] bg-[var(--panel)] px-2 py-1.5 font-mono text-xs"
                      value={headers} onChange={(e) => setHeaders(e.target.value)} placeholder="Authorization=Bearer xyz" />
          </label>
          <div className="sm:col-span-2 flex items-center justify-between">
            <span className="text-[10px] text-[var(--muted)]">{t('projects.creds.note')}</span>
            <button onClick={save} disabled={busy}
                    className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold disabled:opacity-50"
                    style={{ background: 'var(--accent)', color: 'var(--accent-fg)' }}>
              <Save size={13} /> {busy ? t('projects.creds.saving') : t('projects.creds.save')}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

function NewProjectForm({ onDone }: { onDone: () => void }) {
  const t = useT()
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
          <span className="eyebrow">{t('projects.new.name')}</span>
          <input className={inp} value={name} onChange={(e) => setName(e.target.value)} placeholder="Financial App v2" />
        </label>
        <label className="block">
          <span className="eyebrow">{t('projects.new.scope')}</span>
          <input className={inp} value={scope} onChange={(e) => setScope(e.target.value)} placeholder="api.example.com, example.com" />
        </label>
      </div>
      <div className="mt-2">
        <span className="eyebrow">{t('projects.new.schemes')}</span>
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
        <button onClick={onDone} className="rounded-lg border border-[var(--border)] px-3 py-1.5 text-xs font-medium">{t('common.cancel')}</button>
        <button onClick={create} disabled={busy || !name.trim()}
                className="rounded-lg px-3 py-1.5 text-xs font-semibold disabled:opacity-50"
                style={{ background: 'var(--accent)', color: 'var(--accent-fg)' }}>
          {busy ? t('projects.new.creating') : t('projects.new.create')}
        </button>
      </div>
    </div>
  )
}
