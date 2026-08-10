import { useState } from 'react'
import { ScrollText, Inbox, Download, ShieldAlert } from 'lucide-react'
import { usePoll, type AuditEntry } from '../api'
import { Card, Badge, Empty } from '../components/ui'

export function Audit() {
  const { data } = usePoll<AuditEntry[]>('/api/audit', 4000)
  const all = data ?? []
  const [result, setResult] = useState<'all' | 'ok' | 'denied'>('all')
  const [action, setAction] = useState('')
  const [q, setQ] = useState('')

  const denied = all.filter((e) => e.result !== 'ok').length
  const actions = [...new Set(all.map((e) => e.action))].sort()

  const filtered = all.filter((e) => {
    if (result === 'ok' && e.result !== 'ok') return false
    if (result === 'denied' && e.result === 'ok') return false
    if (action && e.action !== action) return false
    if (q) {
      const hay = `${e.user} ${e.role} ${e.action} ${e.target} ${e.detail}`.toLowerCase()
      if (!hay.includes(q.toLowerCase())) return false
    }
    return true
  })
  const rows = [...filtered].reverse()

  const sel = 'rounded-lg border border-[var(--border)] bg-[var(--panel-2)] px-2 py-1 text-xs'

  return (
    <Card
      title={`감사 로그${data ? ` (${all.length})` : ''}`}
      icon={ScrollText}
      right={
        <a href="/audit.csv" className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold"
           style={{ background: 'var(--accent)', color: 'var(--accent-fg)' }} title="규제 제출용 증적 (UTF-8)">
          <Download size={14} /> CSV 내보내기
        </a>
      }
    >
      {all.length === 0 ? (
        <Empty icon={Inbox}>기록된 변경이 없습니다. 프로젝트 생성·전환·스캔·룰 채택 등이 여기에 남습니다.</Empty>
      ) : (
        <>
          {/* 요약 + 필터 */}
          <div className="mb-3 flex flex-wrap items-center gap-2 text-xs">
            <span className="text-[var(--muted)]">총 <b className="text-[var(--text)]">{all.length}</b>건</span>
            <span className="inline-flex items-center gap-1" style={{ color: denied ? 'var(--red)' : 'var(--muted)' }}>
              <ShieldAlert size={13} /> 거부 <b>{denied}</b>건
            </span>
            <span className="mx-1 text-[var(--border)]">|</span>
            <select className={sel} value={result} onChange={(e) => setResult(e.target.value as any)}>
              <option value="all">결과: 전체</option>
              <option value="ok">성공(ok)</option>
              <option value="denied">거부(denied)</option>
            </select>
            <select className={sel} value={action} onChange={(e) => setAction(e.target.value)}>
              <option value="">행위: 전체</option>
              {actions.map((a) => <option key={a} value={a}>{a}</option>)}
            </select>
            <input className={`${sel} w-40`} placeholder="사용자·대상·상세 검색" value={q} onChange={(e) => setQ(e.target.value)} />
            {(result !== 'all' || action || q) && (
              <button className="text-[var(--muted)] underline" onClick={() => { setResult('all'); setAction(''); setQ('') }}>필터해제</button>
            )}
            <span className="ml-auto text-[var(--muted)]">{rows.length}/{all.length} 표시</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-sm [font-variant-numeric:tabular-nums]">
              <thead>
                <tr className="eyebrow text-left">
                  <th className="pb-2 pr-3 font-semibold">Time</th>
                  <th className="pb-2 pr-3 font-semibold">User</th>
                  <th className="pb-2 pr-3 font-semibold">Role</th>
                  <th className="pb-2 pr-3 font-semibold">Action</th>
                  <th className="pb-2 pr-3 font-semibold">Target</th>
                  <th className="pb-2 pr-3 font-semibold">Result</th>
                  <th className="pb-2 pr-3 font-semibold">Detail</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((e, i) => (
                  <tr key={i} className="border-t border-[var(--border)]"
                      style={e.result !== 'ok' ? { background: 'color-mix(in srgb, var(--red) 8%, transparent)' } : undefined}>
                    <td className="py-2 pr-3 font-mono text-xs text-[var(--muted)]">{e.time}</td>
                    <td className="py-2 pr-3 font-medium">{e.user}</td>
                    <td className="py-2 pr-3 text-xs">{e.role}</td>
                    <td className="py-2 pr-3 font-mono text-xs">{e.action}</td>
                    <td className="py-2 pr-3 font-mono text-xs text-[var(--muted)]">{e.target || '—'}</td>
                    <td className="py-2 pr-3">
                      <Badge text={e.result} color={e.result === 'ok' ? 'var(--green)' : 'var(--red)'} />
                    </td>
                    <td className="py-2 pr-3 text-xs text-[var(--muted)]">{e.detail}</td>
                  </tr>
                ))}
                {rows.length === 0 && (
                  <tr><td colSpan={7} className="py-6 text-center text-xs text-[var(--muted)]">필터에 맞는 기록이 없습니다.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}
    </Card>
  )
}
