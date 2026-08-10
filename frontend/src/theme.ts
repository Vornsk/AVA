// 테마: 시스템 설정 자동 감지 → 사용자 토글로 오버라이드(localStorage 기억).
// 최초 fallback 은 다크(브랜드 기본).
export type Theme = 'dark' | 'light'

const KEY = 'cg-theme'

export function initTheme() {
  applyTheme(currentTheme())
}

export function currentTheme(): Theme {
  const saved = localStorage.getItem(KEY) as Theme | null
  if (saved === 'dark' || saved === 'light') return saved
  // 기본은 다크로 고정(브랜드 기본). 사용자가 토글하면 그 선택을 기억한다.
  return 'dark'
}

export function applyTheme(t: Theme) {
  document.documentElement.classList.toggle('dark', t === 'dark')
}

export function toggleTheme(): Theme {
  const next: Theme = currentTheme() === 'dark' ? 'light' : 'dark'
  localStorage.setItem(KEY, next)
  applyTheme(next)
  return next
}
