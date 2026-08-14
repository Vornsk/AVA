import { useState } from 'react'
import { Users as UsersIcon, UserPlus, ShieldCheck, User as UserIcon, Lock, Trash2, KeyRound } from 'lucide-react'
import { usePoll, apiPost, type User, type Me } from '../api'
import { Card, Badge, Empty } from '../components/ui'
import { useT } from '../i18n'

const ROLE_LABEL: Record<string, string> = { leader: '리더', analyst: '수행원' }

export function Users() {
  const t = useT()
  const { data: users } = usePoll<User[]>('/api/users', 5000)
  const { data: me } = usePoll<Me>('/api/me', 10000)
  const canManage = (me?.can ?? []).includes('user:manage')
  const leaderCount = (users ?? []).filter((u) => u.role === 'leader').length

  return (
    <div className="space-y-5">
      {canManage && <CreateUser />}

      <Card title={`${t('users.title')}${users ? ` (${users.length})` : ''}`} icon={UsersIcon}
            right={<span className="text-[11px] text-[var(--muted)]">{t('users.create_only_leader')}</span>}>
        {!users || users.length === 0 ? (
          <Empty icon={UsersIcon}>{t('users.empty')}</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="eyebrow text-left">
                  <th className="pb-2 pr-3 font-semibold">ID</th>
                  <th className="pb-2 pr-3 font-semibold">{t('users.col_name')}</th>
                  <th className="pb-2 pr-3 font-semibold">{t('users.col_role')}</th>
                  {canManage && <th className="pb-2 pr-3 font-semibold">{t('users.col_actions')}</th>}
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id} className="border-t border-[var(--border)]">
                    <td className="py-2.5 pr-3 font-mono text-xs text-[var(--muted)]">{u.id}</td>
                    <td className="py-2.5 pr-3 font-medium">
                      <span className="inline-flex items-center gap-1.5">
                        {u.role === 'leader' ? <ShieldCheck size={14} style={{ color: 'var(--accent)' }} /> : <UserIcon size={14} className="text-[var(--muted)]" />}
                        {u.name}
                        {me?.user?.id === u.id && <span className="text-[10px] text-[var(--muted)]">{t('users.me_marker')}</span>}
                      </span>
                    </td>
                    <td className="py-2.5 pr-3">
                      <Badge text={ROLE_LABEL[u.role] ?? u.role} color={u.role === 'leader' ? 'var(--accent)' : 'var(--muted)'} />
                    </td>
                    {canManage && (
                      <td className="py-2.5 pr-3">
                        <RowActions u={u} isSelf={me?.user?.id === u.id} lastLeader={u.role === 'leader' && leaderCount <= 1} />
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {!canManage && (
        <p className="text-xs text-[var(--muted)]">{t('users.no_create_permission')}{ROLE_LABEL[me?.user?.role ?? ''] ?? me?.user?.role}</p>
      )}
    </div>
  )
}

function RowActions({ u, isSelf, lastLeader }: { u: User; isSelf: boolean; lastLeader: boolean }) {
  const t = useT()
  const [busy, setBusy] = useState(false)
  const btn = 'inline-flex items-center gap-1 rounded-md border border-[var(--border)] px-1.5 py-0.5 text-[11px] disabled:opacity-40'
  const noDelete = isSelf || lastLeader

  async function resetPw() {
    const pw = window.prompt(t('users.new_password_prompt', { name: u.name }))
    if (pw == null) return
    if (pw.length < 6) { alert(t('users.password_min_length')); return }
    setBusy(true)
    try { await apiPost(`/api/users/${u.id}/password`, { password: pw }); alert(t('users.password_reset_done', { name: u.name })) }
    catch (e) { alert(t('users.reset_failed') + e) } finally { setBusy(false) }
  }
  async function del() {
    if (!window.confirm(t('users.delete_confirm', { name: u.name, id: u.id }))) return
    setBusy(true)
    try { await apiPost(`/api/users/${u.id}/delete`, {}) }
    catch (e) { alert(t('users.delete_failed') + e) } finally { setBusy(false) }
  }

  return (
    <div className="flex items-center gap-1">
      <button className={btn} disabled={busy} onClick={resetPw} title={t('users.reset_password_title')}>
        <KeyRound size={11} /> {t('users.btn_password')}
      </button>
      <button className={btn} disabled={busy || noDelete} onClick={del} style={noDelete ? undefined : { color: 'var(--red)' }}
              title={isSelf ? t('users.cannot_delete_self') : lastLeader ? t('users.cannot_delete_last_leader') : t('users.delete_account')}>
        <Trash2 size={11} /> {t('users.btn_delete')}
      </button>
    </div>
  )
}

function CreateUser() {
  const t = useT()
  const [name, setName] = useState('')
  const [role, setRole] = useState('analyst')
  const [pw, setPw] = useState('')
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')

  const valid = name.trim() !== '' && pw.length >= 6

  async function create() {
    setBusy(true); setMsg(''); setErr('')
    try {
      const u = await apiPost<User>('/api/users', { name: name.trim(), role, password: pw })
      setMsg(t('users.created', { name: u.name, role: ROLE_LABEL[u.role] ?? u.role }))
      setName(''); setPw(''); setRole('analyst')
    } catch (e) { setErr(String(e)) } finally { setBusy(false) }
  }

  const inp = 'rounded-lg border border-[var(--border)] bg-[var(--panel-2)] px-2.5 py-1.5 text-sm'

  return (
    <Card title={t('users.create_account')} icon={UserPlus} right={<span className="text-[11px] text-[var(--muted)]">{t('users.create_hint')}</span>}>
      <div className="flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1">
          <span className="text-[11px] text-[var(--muted)]">{t('users.col_name')}</span>
          <input className={inp} value={name} onChange={(e) => setName(e.target.value)} placeholder={t('users.name_placeholder')} autoComplete="off" />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-[11px] text-[var(--muted)]">{t('users.col_role')}</span>
          <select className={inp} value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="analyst">{t('users.role_analyst_option')}</option>
            <option value="leader">{t('users.role_leader_option')}</option>
          </select>
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-[11px] text-[var(--muted)]">{t('users.password_label')} <span className="opacity-70">{t('users.password_hint')}</span></span>
          <span className="inline-flex items-center gap-1.5">
            <Lock size={13} className="text-[var(--muted)]" />
            <input className={inp} type="password" value={pw} onChange={(e) => setPw(e.target.value)} placeholder="••••••" autoComplete="new-password" />
          </span>
        </label>
        <button onClick={create} disabled={busy || !valid}
                className="inline-flex items-center gap-1.5 rounded-lg px-3 py-2 text-sm font-semibold disabled:opacity-50"
                style={{ background: 'var(--accent)', color: 'var(--accent-fg)' }}>
          <UserPlus size={14} /> {busy ? t('users.creating') : t('users.create_account')}
        </button>
      </div>
      {msg && <div className="mt-2 text-xs" style={{ color: 'var(--green)' }}>{msg}</div>}
      {err && <div className="mt-2 text-xs" style={{ color: 'var(--red)' }}>{t('users.create_failed')}{err}</div>}
    </Card>
  )
}
