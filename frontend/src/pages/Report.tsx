import { FileSpreadsheet, Download, Inbox, ListChecks, FileSearch } from 'lucide-react'
import { usePoll } from '../api'
import { Card, Empty, Badge, severityColor } from '../components/ui'

interface ReportRow {
  no: number; target: string; main_url: string; vuln: string; path: string
  url: string; param: string; desc: string; count: number; payload: string; remark: string
  severity: string
}
interface ReportData { headers: string[]; rows: ReportRow[] }

interface EvidenceRow {
  no: number; vuln: string; severity: string; url: string; param: string
  request: string; resp_code: number; response: string
}
interface EvidenceData { headers: string[]; rows: EvidenceRow[] }

const SEV_RANK: Record<string, number> = { high: 0, medium: 1, low: 2, info: 3 }
const sevRank = (s: string) => SEV_RANK[(s || '').toLowerCase()] ?? 9
const sevLabel: Record<string, string> = { high: '높음', medium: '중간', low: '낮음', info: '정보' }
const sevKr = (s: string) => sevLabel[(s || '').toLowerCase()] ?? (s || '—')

function SevBadge({ s }: { s: string }) {
  return <Badge text={sevKr(s)} color={severityColor(s)} />
}

export function Report() {
  const { data } = usePoll<ReportData>('/api/report', 5000)
  const { data: ev } = usePoll<EvidenceData>('/api/evidence', 5000)
  const rows = data?.rows ?? []
  const evRows = ev?.rows ?? []

  // 취약점 유형별 그룹 (심각도 높은 유형 먼저).
  const groupsMap = new Map<string, ReportRow[]>()
  for (const r of rows) {
    const g = groupsMap.get(r.vuln) ?? []
    g.push(r); groupsMap.set(r.vuln, g)
  }
  const groups = [...groupsMap.entries()]
    .map(([vuln, rs]) => ({ vuln, rows: rs, sev: rs.reduce((m, r) => Math.min(m, sevRank(r.severity)), 9) }))
    .sort((a, b) => a.sev - b.sev || b.rows.length - a.rows.length)

  return (
    <div className="space-y-5">
      {/* 1) 산출물 허브 + 요약 */}
      <Card title="산출물" icon={FileSpreadsheet}
            right={
              <div className="flex items-center gap-2">
                <a href="/report.xlsx" className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold"
                   style={{ background: 'var(--accent)', color: 'var(--accent-fg)' }} title="도출리스트 + 증적 시트">
                  <Download size={14} /> 도출리스트 .xlsx
                </a>
                <a href="/coverage.xlsx" className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border)] px-3 py-1.5 text-xs font-semibold"
                   title="선택 점검항목표 전체의 수행결과(양호/취약/미점검)">
                  <ListChecks size={14} /> 점검결과표 .xlsx
                </a>
              </div>
            }>
        <p className="mb-3 text-xs text-[var(--muted)]">
          <b className="text-[var(--text)]">도출리스트</b>(취약점 목록·증적) + <b className="text-[var(--text)]">점검결과표</b>(전 항목 수행결과) 두 산출물을 제출합니다.
          도출리스트 xlsx에는 <b className="text-[var(--text)]">증적 시트</b>(재현요청·증명응답)가 함께 들어 있습니다.
        </p>
        {rows.length === 0 ? (
          <span className="text-xs text-[var(--muted)]">도출된 취약점 없음</span>
        ) : (
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-[var(--muted)]">총 <b className="text-[var(--text)]">{rows.length}</b>건 · 증적 <b className="text-[var(--text)]">{evRows.length}</b>건 ·</span>
            {groups.map((g) => (
              <span key={g.vuln} className="inline-flex items-center gap-1 rounded-full border border-[var(--border)] px-2 py-0.5 text-[11px]">
                <span className="h-2 w-2 rounded-full" style={{ background: severityColor(['high','medium','low','info'][g.sev] ?? 'info') }} />
                {g.vuln} <b>{g.rows.length}</b>
              </span>
            ))}
          </div>
        )}
      </Card>

      {/* 2) 도출리스트 — 유형별 그룹 + 심각도 */}
      <Card title={`도출리스트 (${rows.length}건)`} icon={FileSpreadsheet}>
        {rows.length === 0 ? (
          <Empty icon={Inbox}>도출할 finding 이 없습니다. 스캔을 실행하면 여기에 표시됩니다.</Empty>
        ) : (
          <div className="space-y-4">
            {groups.map((g) => (
              <div key={g.vuln}>
                <div className="mb-1.5 flex items-center gap-2">
                  <SevBadge s={['high','medium','low','info'][g.sev] ?? 'info'} />
                  <span className="text-sm font-semibold">{g.vuln}</span>
                  <span className="text-xs text-[var(--muted)]">{g.rows.length}건</span>
                </div>
                <div className="overflow-x-auto rounded-lg border border-[var(--border)]">
                  <table className="w-full text-xs [font-variant-numeric:tabular-nums]">
                    <thead>
                      <tr className="eyebrow text-left">
                        <th className="whitespace-nowrap px-2 py-1.5 font-semibold">NO</th>
                        <th className="px-2 py-1.5 font-semibold">대상</th>
                        <th className="px-2 py-1.5 font-semibold">발견 URL</th>
                        <th className="px-2 py-1.5 font-semibold">파라미터</th>
                        <th className="px-2 py-1.5 font-semibold">설명</th>
                        <th className="px-2 py-1.5 font-semibold">비고</th>
                      </tr>
                    </thead>
                    <tbody>
                      {g.rows.map((r) => (
                        <tr key={r.no} className="border-t border-[var(--border)] align-top">
                          <td className="px-2 py-1.5">{r.no}</td>
                          <td className="px-2 py-1.5 font-medium">{r.target}</td>
                          <td className="px-2 py-1.5 font-mono text-[var(--muted)]">{r.path}</td>
                          <td className="px-2 py-1.5 font-mono">{r.param || '—'}</td>
                          <td className="max-w-[280px] px-2 py-1.5 text-[var(--muted)]">{r.desc}</td>
                          <td className="whitespace-nowrap px-2 py-1.5 text-[var(--muted)]">{r.remark}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* 3) 증적 (FR-4.2) 미리보기 */}
      <Card title={`증적 (${evRows.length}건)`} icon={FileSearch}>
        <p className="mb-3 text-xs text-[var(--muted)]">
          각 발견을 뒷받침하는 <b className="text-[var(--text)]">재현 요청</b>과 <b className="text-[var(--text)]">증명 응답</b>(민감정보 마스킹)입니다. 다운로드 없이 여기서 검토하세요.
        </p>
        {evRows.length === 0 ? (
          <Empty icon={Inbox}>증적(재현요청·응답)이 있는 finding 이 없습니다.</Empty>
        ) : (
          <div className="space-y-2">
            {evRows.map((e) => (
              <details key={e.no} className="rounded-lg border border-[var(--border)] px-3 py-2">
                <summary className="flex cursor-pointer items-center gap-2 text-sm">
                  <SevBadge s={e.severity} />
                  <span className="font-medium">{e.vuln}</span>
                  <span className="font-mono text-xs text-[var(--muted)]">{e.url}{e.param ? ` · ${e.param}` : ''}</span>
                  <span className="ml-auto font-mono text-[11px] text-[var(--muted)]">HTTP {e.resp_code || '—'}</span>
                </summary>
                <div className="mt-2 space-y-2">
                  <div>
                    <div className="eyebrow mb-1">재현 요청</div>
                    <pre className="overflow-x-auto rounded bg-[var(--panel-2)] p-2 font-mono text-[11px] leading-relaxed">{e.request || '—'}</pre>
                  </div>
                  <div>
                    <div className="eyebrow mb-1">증명 응답 (마스킹)</div>
                    <pre className="max-h-60 overflow-auto rounded bg-[var(--panel-2)] p-2 font-mono text-[11px] leading-relaxed">{e.response || '—'}</pre>
                  </div>
                </div>
              </details>
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}
