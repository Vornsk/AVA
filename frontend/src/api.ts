// 백엔드 읽기전용 JSON API 타입 + fetch 훅.
import { useEffect, useRef, useState } from 'react'

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
  const res = await fetch(path, { headers: { Accept: 'application/json' } })
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
  }, [path, ms])

  return { data, error, loading }
}
