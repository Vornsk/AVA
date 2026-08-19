// 백엔드 읽기전용 JSON API 타입 + fetch 훅.
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { currentLang, useI18n } from './i18n'

export interface Stats {
  endpoints: number
  hosts: number
  findings: number
  scanruns: number
  scope: string[]
  schemes: string[]
  safe_mode: boolean
  ca_trusted: boolean
  rules: number
  detectors: number
  llm_provider: string
  risk_profile: string
  retention_days?: number // 휴지통 자동 영구삭제 보존기간(일) — D-n 표시용 (이슈 #15)
}

export interface Finding {
  id: string
  scan_run: string
  vuln: string
  severity: string
  host: string
  path: string
  method: string
  param?: string
  kind: string
  detector: string
  vuln_def?: string
  check_items?: string[]
  confidence: string
  evidence?: string
  request?: string
  response?: string
  resp_code?: number
  status: string
  version: number
  reviewer?: string
  time?: string
  llm_verdict?: string
  llm_reason?: string
  remediation?: string
  reverify_status?: string // 조치완료 | 미조치 | 부분조치 | 신규발생 (미설정=미점검)
}

export interface ScanRun {
  id: string
  status: string
  targets: number
  detectors: string[] | null
  skipped?: string[]
  total: number
  done: number
  findings: number
  safe_mode?: boolean
}

export interface CheckItem {
  id: string
  scheme: string
  control?: string
  vuln: string
  risk?: number
}

export interface ItemStatus {
  check_item: CheckItem
  vuln_name: string
  detectors?: string[]
  automatable: boolean
  available: boolean
  ran: boolean
  findings: number
  status: string
}

export interface SchemeCoverage {
  scheme: string
  total: number
  automatable: number
  ran: number
  vulnerable: number
  manual: number
  items: ItemStatus[]
}

export interface CoverageReport {
  schemes: SchemeCoverage[] | null
}

export interface Param {
  name: string
  in: string
  type?: string
  required?: boolean
  sample?: string
  mined?: boolean     // 파라미터 마이닝으로 발견 — 관측이 아닌 능동 주입 (#40)
}
export interface Target {
  host: string
  path: string
  methods?: string[]
  params?: Param[]
  auth_required?: boolean
  verdict?: string
  count?: number
  first_seen?: string
  last_seen?: string
  source?: string     // 출처 신뢰도 등급 spec|traffic|headless-xhr|discover|crawl-link|static-regex (#25·#26·#27)
  unverified?: boolean // 라이브니스 프로브 미통과 — 기본 숨김 (#26·#28)
  auth_only?: boolean  // 인증 뒤에만 보이는 표면 (인증 델타, #38)
}
export interface Rule {
  name: string
  action: string // block | allow
  methods?: string[]
  path_pattern?: string
  reason?: string
}
export interface DetectorInfo {
  id: string
  name: string
  destructive: boolean
  tool?: string
  available?: boolean
  version?: string
}
export interface LLMDecision {
  id: number
  input: { method: string; path: string; param_keys?: string[]; content_type?: string; hint?: string }
  verdict: { allow: boolean; reason: string; confidence: number; provider?: string; model?: string }
  cached: boolean
}
export interface ReverifyItem {
  finding_id: string
  vuln: string
  vuln_def?: string
  target: string
  detector: string
  verdict: string // 조치완료 | 미조치 | 부분조치 | 신규발생 | 미확인
  reproduced: boolean
  detail?: string
  time: string
}
export interface ReverifyRun {
  id: string
  source: string
  total: number
  fixed: number
  open: number
  unknown: number
  results: ReverifyItem[]
  time: string
}

export interface RuleCandidate {
  signature: string
  method: string
  path: string
  verdict: string // block | allow
  hits: number
  consistency: number // 0..1
  avg_confidence: number
  deterministic: boolean
  samples: number[]
  est_savings: number
  warning?: string
  status: string
  draft_rule: Rule
}

export interface ScanDiff {
  from: string
  to: string
  added: Finding[]
  removed: Finding[]
  common: number
}

export interface Project {
  id: string
  name: string
  owner?: string
  members?: string[]
  main_url: string
  scope: string[]
  allow_paths?: string[]
  exclude_paths?: string[]
  schemes?: string[]
  created: string
  modified: string
  deleted_at?: string // 소프트 삭제 시각(휴지통). 빈 값=정상 (이슈 #14)
}

export interface User {
  id: string
  name: string
  role: string // leader | analyst
}
export interface Me {
  user: User
  can: string[]
  auth_disabled?: boolean
}
export interface AuditEntry {
  time: string
  user: string
  role: string
  action: string
  target: string
  result: string // ok | denied
  detail?: string
}

export interface CrawlResult {
  id: string
  seed: string
  status: string
  pages: number
  found: number
  js: number
  mode: string
  queued: number
  errors: number
  mined?: number      // 파라미터 마이닝으로 발견한 hidden 파라미터 수 (#40)
  started: string
}

export interface TenantInfo {
  project_id: string
  port: number
  scope: string[]
  endpoints: number
  traffic: number
  started: string
}

export interface CredSummary {
  has_creds: boolean
  cookies?: string[]
  headers?: string[]
  identities?: string[]
}

export interface AuthIdentity { name: string; cookies: string[]; headers: string[] }
export interface AuthSummary {
  enabled: boolean
  cookies: string[] | null
  headers: string[] | null
  identities: AuthIdentity[]
}
export interface ProxyStatus {
  listen: string
  capturing: boolean
  scope_hosts: number
  captured_requests: number
  endpoints: number
  hosts: number
}
export interface LoginSeqInfo {
  enabled: boolean
  url: string
  method: string
  token_url: string
  token_field: string
  token_param: string
  logged_out: string
  fields: string[] // 필드 키만(값 미노출)
}

async function getJSON<T>(path: string): Promise<T> {
  // X-Lang: 화면 언어를 백엔드에 전달 → 로케일 콘텐츠 응답(advisor 등, #18)
  const res = await fetch(path, { headers: { Accept: 'application/json', 'X-Lang': currentLang() } })
  if (!res.ok) throw new Error(`${path} → ${res.status}`)
  return res.json() as Promise<T>
}

// apiGet — 온디맨드 단발 조회 (파라미터 기반 요청 등, 폴링 아님).
export function apiGet<T>(path: string): Promise<T> { return getJSON<T>(path) }

// apiPost — 프로젝트 관리 등 mutation (§5.1).
export async function apiPost<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error(`${path} → ${res.status}`)
  return res.json() as Promise<T>
}

// usePoll — 주기적으로 API 를 폴링해 라이브 느낌. 컴포넌트 언마운트 시 정지.
export function usePoll<T>(path: string, ms = 4000) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const timer = useRef<number | undefined>(undefined)
  const { lang } = useI18n() // 언어 변경 시 즉시 재요청(X-Lang 반영)

  useEffect(() => {
    let alive = true
    const tick = async () => {
      try {
        const d = await getJSON<T>(path)
        if (alive) { setData(d); setError(null) }
      } catch (e) {
        if (alive) setError(String(e))
      } finally {
        if (alive) setLoading(false)
      }
    }
    tick()
    timer.current = window.setInterval(tick, ms)
    return () => { alive = false; window.clearInterval(timer.current) }
  }, [path, ms, lang])

  return { data, error, loading }
}

// ── 취약점 카탈로그 로케일 (#18) ──
export interface VulnDef {
  id: string
  name: string
  desc: string
  name_en?: string
  desc_en?: string
  detectors?: string[]
  cwe?: string
}

// useLocName — finding.vuln_def(안정 ID)로 화면 취약점명을 로케일 해석하는 함수 반환.
// en 이고 카탈로그에 영문명이 있으면 영문, 아니면 fallback(저장된 한글명).
export function useLocName() {
  const { data } = usePoll<VulnDef[]>('/api/vulndefs', 60000)
  const { lang } = useI18n()
  const map = useMemo(() => {
    const m: Record<string, VulnDef> = {}
    for (const v of data ?? []) m[v.id] = v
    return m
  }, [data])
  return useCallback(
    (vulnDef: string | undefined, fallback: string) => {
      if (lang === 'en' && vulnDef && map[vulnDef]?.name_en) return map[vulnDef].name_en as string
      return fallback
    },
    [map, lang],
  )
}
