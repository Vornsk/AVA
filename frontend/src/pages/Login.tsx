import { useState } from 'react'
import { LogIn } from 'lucide-react'
import { AvaMark } from '../components/AvaMark'

export function Login({ onSuccess }: { onSuccess: () => void }) {
  const [username, setU] = useState('leader')
  const [password, setP] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true); setErr('')
    try {
      const res = await fetch('/api/login', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      })
      if (!res.ok) { setErr('아이디 또는 비밀번호가 올바르지 않습니다.'); return }
      onSuccess()
    } catch {
      setErr('서버에 연결할 수 없습니다.')
    } finally { setBusy(false) }
  }

  const inp = 'w-full rounded-lg border border-[var(--border)] bg-[var(--panel-2)] px-3 py-2 text-sm outline-none focus:border-[var(--accent)]'

  return (
    <div className="flex min-h-full items-center justify-center p-6">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center gap-2 text-center">
          <div className="grid h-12 w-12 place-items-center rounded-2xl shadow-[var(--shadow)]"
               style={{ background: 'linear-gradient(135deg, var(--accent), color-mix(in srgb, var(--accent) 60%, #000))', color: 'var(--accent-fg)' }}>
            <AvaMark size={26} />
          </div>
          <div>
            <div className="text-xl font-extrabold tracking-[0.02em]">AVA</div>
            <div className="text-[11px] font-semibold uppercase tracking-[0.12em] text-[var(--muted)]">Automated Vulnerability Assessment</div>
          </div>
        </div>

        <form onSubmit={submit}
              className="rounded-xl border border-[var(--border)] bg-[var(--panel)] p-5 shadow-[var(--shadow)]">
          <div className="space-y-3">
            <label className="block">
              <span className="eyebrow">사용자</span>
              <input className={inp} value={username} onChange={(e) => setU(e.target.value)} autoFocus />
            </label>
            <label className="block">
              <span className="eyebrow">비밀번호</span>
              <input className={inp} type="password" value={password} onChange={(e) => setP(e.target.value)} placeholder="••••••••" />
            </label>
          </div>
          {err && <div className="mt-3 text-xs" style={{ color: 'var(--red)' }}>{err}</div>}
          <button type="submit" disabled={busy}
                  className="mt-4 flex w-full items-center justify-center gap-1.5 rounded-lg px-3 py-2 text-sm font-semibold disabled:opacity-50"
                  style={{ background: 'var(--accent)', color: 'var(--accent-fg)' }}>
            <LogIn size={15} /> {busy ? '로그인 중…' : '로그인'}
          </button>
        </form>

        <p className="mt-4 text-center text-[11px] text-[var(--muted)]">
          데모 계정 — leader / leader123 · analyst / analyst123 <br />(운영 배포 시 반드시 변경)
        </p>
      </div>
    </div>
  )
}
