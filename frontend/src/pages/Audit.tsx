import { useState } from 'react'
import { ScrollText, Inbox, Download, ShieldAlert } from 'lucide-react'
import { usePoll, type AuditEntry } from '../api'
import { Card, Badge, Empty } from '../components/ui'
import { useT } from '../i18n'

export function Audit() {
  const t = useT()
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
      title={`${t('audit.title')}${data ? ` (${all.length})` : ''}`}
      icon={ScrollText}
      right={
        <a href="/audit.csv" className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold"
           style={{ background: 'var(--accent)', color: 'var(--accent-fg)' }} title={t('audit.csvTitle')}>
          <Download size={14} /> {t('audit.exportCsv')}
        </a>
      }
    >
      {all.length === 0 ? (
        <Empty icon={Inbox}>{t('audit.empty')}</Empty>
      ) : (
        <>
          {/* 요약 + 필터 */}
          <div className="mb-3 flex flex-wrap items-center gap-2 text-xs">
            <span className="text-[var(--muted)]">{t('audit.totalPre')}<b className="text-[var(--text)]">{all.length}</b>{t('audit.countSuffix')}</span>
            <span className="inline-flex items-center gap-1" style={{ color: denied ? 'var(--red)' : 'var(--muted)' }}>
              <ShieldAlert size={13} /> {t('audit.deniedPre')}<b>{denied}</b>{t('audit.countSuffix')}
            </span>
            <span className="mx-1 text-[var(--border)]">|</span>
            <select className={sel} value={result} onChange={(e) => setResult(e.target.value as any)}>
              <option value="all">{t('audit.resultAll')}</option>
              <option value="ok">{t('audit.resultOk')}</option>
              <option value="denied">{t('audit.resultDenied')}</option>
            </select>
            <select className={sel} value={action} onChange={(e) => setAction(e.target.value)}>
              <option value="">{t('audit.actionAll')}</option>
              {actions.map((a) => <option key={a} value={a}>{a}</option>)}
            </select>
            <input className={`${sel} w-40`} placeholder={t('audit.searchPlaceholder')} value={q} onChange={(e) => setQ(e.target.value)} />
            {(result !== 'all' || action || q) && (
              <button className="text-[var(--muted)] underline" onClick={() => { setResult('all'); setAction(''); setQ('') }}>{t('audit.clearFilter')}</button>
            )}
            <span className="ml-auto text-[var(--muted)]">{t('audit.shown', { shown: rows.length, total: all.length })}</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-sm [font-variant-numeric:tabular-nums]">
              <thead>
                <tr className="eyebrow text-left">
                  <th className="pb-2 pr-3 font-semibold">{t('audit.colTime')}</th>
                  <th className="pb-2 pr-3 font-semibold">{t('audit.colUser')}</th>
                  <th className="pb-2 pr-3 font-semibold">{t('audit.colRole')}</th>
                  <th className="pb-2 pr-3 font-semibold">{t('audit.colAction')}</th>
                  <th className="pb-2 pr-3 font-semibold">{t('audit.colTarget')}</th>
                  <th className="pb-2 pr-3 font-semibold">{t('audit.colResult')}</th>
                  <th className="pb-2 pr-3 font-semibold">{t('audit.colDetail')}</th>
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
                  <tr><td colSpan={7} className="py-6 text-center text-xs text-[var(--muted)]">{t('audit.noMatch')}</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}
    </Card>
  )
}
