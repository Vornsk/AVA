import { useState } from 'react'
import { Users as UsersIcon, UserPlus, ShieldCheck, User as UserIcon, Lock, Trash2, KeyRound } from 'lucide-react'
import { usePoll, apiPost, type User, type Me } from '../api'
import { Card, Badge, Empty } from '../components/ui'

const ROLE_LABEL: Record<string, string> = { leader: '리더', analyst: '수행원' }

export function Users() {
  const { data: users } = usePoll<User[]>('/api/users', 5000)
  const { data: me } = usePoll<Me>('/api/me', 10000)
  const canManage = (me?.can ?? []).includes('user:manage')
  const leaderCount = (users ?? []).filter((u) => u.role === 'leader').length

  return (
    <div className="space-y-5">
      {canManage && <CreateUser />}

      <Card title={`사용자${users ? ` (${users.length})` : ''}`} icon={UsersIcon}
            right={<span className="text-[11px] text-[var(--muted)]">계정 생성은 리더만 가능</span>}>
        {!users || users.length === 0 ? (
          <Empty icon={UsersIcon}>등록된 사용자가 없습니다.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="eyebrow text-left">
                  <th className="pb-2 pr-3 font-semibold">ID</th>
                  <th className="pb-2 pr-3 font-semibold">이름</th>
                  <th className="pb-2 pr-3 font-semibold">역할</th>
                  {canManage && <th className="pb-2 pr-3 font-semibold">작업</th>}
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
                        {me?.user?.id === u.id && <span className="text-[10px] text-[var(--muted)]">(나)</span>}
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
        <p className="text-xs text-[var(--muted)]">계정 생성 권한이 없습니다(리더 전용). 현재 역할: {ROLE_LABEL[me?.user?.role ?? ''] ?? me?.user?.role}</p>
      )}
    </div>
  )
}

function RowActions({ u, isSelf, lastLeader }: { u: User; isSelf: boolean; lastLeader: boolean }) {
  const [busy, setBusy] = useState(false)
  const btn = 'inline-flex items-center gap-1 rounded-md border border-[var(--border)] px-1.5 py-0.5 text-[11px] disabled:opacity-40'
  const noDelete = isSelf || lastLeader

  async function resetPw() {
    const pw = window.prompt(`${u.name}의 새 비밀번호 (6자 이상)`)
    if (pw == null) return
    if (pw.length < 6) { alert('비밀번호는 6자 이상이어야 합니다'); return }
    setBusy(true)
    try { await apiPost(`/api/users/${u.id}/password`, { password: pw }); alert(`${u.name} 비밀번호를 재설정했습니다.`) }
    catch (e) { alert('재설정 실패: ' + e) } finally { setBusy(false) }
  }
  async function del() {
    if (!window.confirm(`${u.name}(${u.id}) 계정을 삭제할까요? 되돌릴 수 없습니다.`)) return
    setBusy(true)
    try { await apiPost(`/api/users/${u.id}/delete`, {}) }
    catch (e) { alert('삭제 실패: ' + e) } finally { setBusy(false) }
  }

  return (
    <div className="flex items-center gap-1">
      <button className={btn} disabled={busy} onClick={resetPw} title="비밀번호 재설정">
        <KeyRound size={11} /> 비번
      </button>
      <button className={btn} disabled={busy || noDelete} onClick={del} style={noDelete ? undefined : { color: 'var(--red)' }}
              title={isSelf ? '자기 자신은 삭제 불가' : lastLeader ? '마지막 리더는 삭제 불가' : '계정 삭제'}>
        <Trash2 size={11} /> 삭제
      </button>
    </div>
  )
}

function CreateUser() {
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
      setMsg(`${u.name}(${ROLE_LABEL[u.role] ?? u.role}) 계정을 생성했습니다.`)
      setName(''); setPw(''); setRole('analyst')
    } catch (e) { setErr(String(e)) } finally { setBusy(false) }
  }

  const inp = 'rounded-lg border border-[var(--border)] bg-[var(--panel-2)] px-2.5 py-1.5 text-sm'

  return (
    <Card title="계정 생성" icon={UserPlus} right={<span className="text-[11px] text-[var(--muted)]">리더 전용 · 비밀번호는 bcrypt로만 저장</span>}>
      <div className="flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1">
          <span className="text-[11px] text-[var(--muted)]">이름</span>
          <input className={inp} value={name} onChange={(e) => setName(e.target.value)} placeholder="예: analyst2" autoComplete="off" />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-[11px] text-[var(--muted)]">역할</span>
          <select className={inp} value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="analyst">수행원 (진단 수행)</option>
            <option value="leader">리더 (관리·승인)</option>
          </select>
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-[11px] text-[var(--muted)]">비밀번호 <span className="opacity-70">(6자 이상)</span></span>
          <span className="inline-flex items-center gap-1.5">
            <Lock size={13} className="text-[var(--muted)]" />
            <input className={inp} type="password" value={pw} onChange={(e) => setPw(e.target.value)} placeholder="••••••" autoComplete="new-password" />
          </span>
        </label>
        <button onClick={create} disabled={busy || !valid}
                className="inline-flex items-center gap-1.5 rounded-lg px-3 py-2 text-sm font-semibold disabled:opacity-50"
                style={{ background: 'var(--accent)', color: 'var(--accent-fg)' }}>
          <UserPlus size={14} /> {busy ? '생성 중…' : '계정 생성'}
        </button>
      </div>
      {msg && <div className="mt-2 text-xs" style={{ color: 'var(--green)' }}>{msg}</div>}
      {err && <div className="mt-2 text-xs" style={{ color: 'var(--red)' }}>생성 실패: {err}</div>}
    </Card>
  )
}
