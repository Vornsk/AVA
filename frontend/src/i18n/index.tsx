// 경량 무의존 i18n — React Context 기반. Phase 1(UI 크롬 ko/en).
// - 카탈로그는 타입드 TS 모듈(ko.ts/en.ts). en 은 ko 의 키 전체를 강제(컴파일 검사).
// - 백엔드에서 내려오는 콘텐츠(취약점명·상태값 등)는 Phase 2 범위 → 여기서 다루지 않는다.
import { createContext, useCallback, useContext, useState, type ReactNode } from 'react'
import { ko } from './ko'
import { en } from './en'

export type Lang = 'ko' | 'en'
export type MsgKey = keyof typeof ko
export type Vars = Record<string, string | number>

const CATALOGS: Record<Lang, Record<MsgKey, string>> = { ko, en }
const KEY = 'cg-lang'

export function currentLang(): Lang {
  const saved = localStorage.getItem(KEY)
  if (saved === 'ko' || saved === 'en') return saved
  return 'ko' // 기본 ko(브랜드 기본)
}

// {name} 형태의 플레이스홀더를 vars 로 치환. 누락 키는 원문 유지.
function format(tpl: string, vars?: Vars): string {
  if (!vars) return tpl
  return tpl.replace(/\{(\w+)\}/g, (_, k: string) => (k in vars ? String(vars[k]) : `{${k}}`))
}

type Ctx = {
  lang: Lang
  setLang: (l: Lang) => void
  t: (k: MsgKey, vars?: Vars) => string
}

const I18nContext = createContext<Ctx | null>(null)

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(currentLang())

  const setLang = useCallback((l: Lang) => {
    localStorage.setItem(KEY, l)
    document.documentElement.setAttribute('lang', l)
    setLangState(l)
  }, [])

  const t = useCallback(
    (k: MsgKey, vars?: Vars) => format(CATALOGS[lang][k] ?? ko[k] ?? k, vars),
    [lang],
  )

  return <I18nContext.Provider value={{ lang, setLang, t }}>{children}</I18nContext.Provider>
}

export function useI18n(): Ctx {
  const ctx = useContext(I18nContext)
  if (!ctx) throw new Error('useI18n must be used within <I18nProvider>')
  return ctx
}

// 컴포넌트에서 문구만 필요할 때: const t = useT()
export function useT() {
  return useI18n().t
}
