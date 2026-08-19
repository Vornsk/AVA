import { useState, type ReactNode } from 'react'
import { ChevronDown, HelpCircle, type LucideIcon } from 'lucide-react'
import { useI18n } from '../i18n'

// 상태/판정/심각도 값(백엔드 도메인값)의 영문 표시 라벨 (#18).
// 원시값은 색상 매핑 키로 그대로 두고, en 에서 표시 라벨만 이 맵으로 치환한다.
const STATUS_EN: Record<string, string> = {
  // 커버리지
  '취약': 'Vulnerable', '양호': 'Good', '미점검': 'Unchecked', '해당없음': 'N/A',
  '미지원(도구없음)': 'Unsupported (no tool)', '미지원(수동)': 'Unsupported (manual)',
  // finding 검토 상태
  '신규': 'New', '검토중': 'Reviewing', '확정': 'Confirmed', '오탐': 'False positive',
  '보류': 'On hold', '보고': 'Reported',
  // 이행점검 판정
  '조치완료': 'Fixed', '미조치': 'Open', '부분조치': 'Partial', '신규발생': 'New (regression)',
  '미확인': 'Unknown',
  // ScanRun / crawl 상태
  '진행': 'Running', '완료': 'Done', '일시정지': 'Paused', '중단': 'Stopped',
  // advisor
  '제안': 'Proposed',
  // 스킴명
  '주요정보통신기반시설': 'Critical Infrastructure (KII)', '전자금융': 'E-Finance', '모바일': 'Mobile',
  // 미지원 축약(커버리지 요약 범례)
  '미지원': 'Unsupported',
  // 심각도(영문 enum 대문자화)
  'high': 'High', 'medium': 'Medium', 'low': 'Low', 'info': 'Info',
}

// useStatusLabel — 표시 라벨 로케일 해석. en 이고 매핑이 있으면 영문, 아니면 원문.
// Dot/Badge 외에 상태 드롭다운 옵션 라벨 등에서도 재사용.
export function useStatusLabel() {
  const { lang } = useI18n()
  return (text: string) => (lang === 'en' ? STATUS_EN[text] ?? STATUS_EN[text?.toLowerCase?.()] ?? text : text)
}

export function Card({ title, icon: Icon, right, children, className = '', pad = true, collapsible = false, defaultOpen = true, muted = false }: {
  title?: ReactNode; icon?: LucideIcon; right?: ReactNode; children: ReactNode; className?: string; pad?: boolean
  collapsible?: boolean; defaultOpen?: boolean; muted?: boolean // #28 정보 위계 — 참고 카드는 접기 가능
}) {
  const [open, setOpen] = useState(defaultOpen)
  const header = (title || right) && (
    <div className={`flex items-center justify-between px-5 py-3.5 ${(!collapsible || open) ? 'border-b border-[var(--border)]' : ''}`}>
      <h3 className={`flex items-center gap-2 text-sm font-semibold ${muted ? 'text-[var(--muted)]' : ''}`}>
        {collapsible && <ChevronDown size={14} className={`text-[var(--muted)] transition-transform ${open ? '' : '-rotate-90'}`} />}
        {Icon && <Icon size={15} strokeWidth={2} style={{ color: muted ? 'var(--muted)' : 'var(--accent)' }} />}
        {title}
      </h3>
      {right}
    </div>
  )
  return (
    <div className={`rounded-xl border bg-[var(--panel)] border-[var(--border)] shadow-[var(--shadow)] ${className}`}>
      {collapsible && header ? (
        <button type="button" onClick={() => setOpen((v) => !v)} className="w-full text-left hover:bg-[var(--panel-2)] rounded-t-xl">{header}</button>
      ) : header}
      {(!collapsible || open) && <div className={pad ? 'p-5' : ''}>{children}</div>}
    </div>
  )
}

// Tooltip — 요소에 hover/포커스 시 설명을 띄운다 (#28 용어 도움말).
export function Tooltip({ label, children, className = '' }: { label: string; children: ReactNode; className?: string }) {
  const [show, setShow] = useState(false)
  return (
    <span className={`relative inline-flex ${className}`} tabIndex={0}
          onMouseEnter={() => setShow(true)} onMouseLeave={() => setShow(false)}
          onFocus={() => setShow(true)} onBlur={() => setShow(false)}>
      {children}
      {show && (
        <span role="tooltip"
              className="pointer-events-none absolute bottom-full left-1/2 z-30 mb-1.5 w-max max-w-[240px] -translate-x-1/2 whitespace-normal rounded-md border border-[var(--border)] bg-[var(--panel)] px-2.5 py-1.5 text-left text-[11px] font-normal leading-snug text-[var(--text)] shadow-[var(--shadow)]">
          {label}
        </span>
      )}
    </span>
  )
}

// InfoTip — ? 아이콘 하나로 도움말을 붙인다.
export function InfoTip({ label }: { label: string }) {
  return (
    <Tooltip label={label} className="align-middle">
      <HelpCircle size={12} className="cursor-help text-[var(--muted)] hover:text-[var(--text)]" />
    </Tooltip>
  )
}

export function Stat({ label, value, icon: Icon, accent, hint }: {
  label: string; value: ReactNode; icon?: LucideIcon; accent?: string; hint?: string
}) {
  const c = accent ?? 'var(--accent)'
  return (
    <div className="rounded-xl border bg-[var(--panel)] border-[var(--border)] shadow-[var(--shadow)] p-4">
      <div className="flex items-start justify-between">
        <div className="eyebrow">{label}</div>
        {Icon && (
          <span className="grid h-7 w-7 place-items-center rounded-lg"
                style={{ color: c, background: `color-mix(in srgb, ${c} 14%, transparent)` }}>
            <Icon size={15} strokeWidth={2} />
          </span>
        )}
      </div>
      <div className="mt-2 text-[26px] font-bold leading-none">{value}</div>
      {hint && <div className="mt-1.5 text-xs text-[var(--muted)]">{hint}</div>}
    </div>
  )
}

const SEVERITY: Record<string, string> = {
  high: 'var(--red)', medium: 'var(--amber)', low: 'var(--blue)', info: 'var(--muted)',
}
const STATUS: Record<string, string> = {
  '취약': 'var(--red)',
  '양호': 'var(--green)',
  '미점검': 'var(--amber)',
  '해당없음': 'var(--muted)',
  '미지원(도구없음)': 'var(--muted)',
  '미지원(수동)': 'var(--muted)',
  // finding 검토 상태머신 (FR-4.4)
  '신규': 'var(--blue)', '검토중': 'var(--amber)', '확정': 'var(--red)',
  '오탐': 'var(--muted)', '보류': 'var(--muted)', '보고': 'var(--green)',
  // 이행점검 판정 (FR-5.3)
  '조치완료': 'var(--green)', '미조치': 'var(--red)', '부분조치': 'var(--amber)',
  '신규발생': 'var(--blue)', '미확인': 'var(--muted)',
  // ScanRun 상태
  '진행': 'var(--blue)', '완료': 'var(--green)', '일시정지': 'var(--amber)', '중단': 'var(--red)',
}

export function Badge({ text, color, dot }: { text: string; color?: string; dot?: boolean }) {
  const label = useStatusLabel()
  const c = color ?? SEVERITY[text.toLowerCase()] ?? STATUS[text] ?? 'var(--muted)' // 색상은 원시값 기준
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-medium"
      style={{ color: c, backgroundColor: `color-mix(in srgb, ${c} 14%, transparent)` }}
    >
      {dot && <span className="h-1.5 w-1.5 rounded-full" style={{ background: c }} />}
      {label(text)}
    </span>
  )
}

// Dot — 텍스트 상태 표시(테이블용). 배지보다 가벼움.
export function Dot({ text, color }: { text: string; color?: string }) {
  const label = useStatusLabel()
  const c = color ?? STATUS[text] ?? 'var(--muted)' // 색상은 원시값 기준
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium" style={{ color: c }}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: c }} />{label(text)}
    </span>
  )
}

export function severityColor(s: string) { return SEVERITY[s?.toLowerCase()] ?? 'var(--muted)' }
export function statusColor(s: string) { return STATUS[s] ?? 'var(--muted)' }

export function Empty({ icon: Icon, children }: { icon?: LucideIcon; children: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-2 py-12 text-center text-sm text-[var(--muted)]">
      {Icon && <Icon size={26} strokeWidth={1.5} className="opacity-50" />}
      {children}
    </div>
  )
}
