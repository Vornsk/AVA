// AvaMark — AVA(Automated Vulnerability Assessment) 로고 마크.
// currentColor 로만 그려서 accent 타일 위 흰색으로 렌더 → 다크/라이트 동일하게 보인다(테마 무관).
export type AvaVariant = 'beacon' | 'target' | 'shield'

export function AvaMark({ size = 20, variant = 'beacon' }: { size?: number; variant?: AvaVariant }) {
  const common = {
    width: size, height: size, viewBox: '0 0 24 24', fill: 'none',
    stroke: 'currentColor', strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const,
    'aria-hidden': true,
  }
  if (variant === 'target') {
    // A(위 꼭짓점) + V(아래 꼭짓점) + 중앙 스캔 노드 — "AVA"를 스캔 타깃으로 형상화.
    return (
      <svg {...common} strokeWidth={2.1}>
        <path d="M5.5 10.5 12 4l6.5 6.5" />
        <path d="M5.5 13.5 12 20l6.5-6.5" />
        <circle cx="12" cy="12" r="1.7" fill="currentColor" stroke="none" />
      </svg>
    )
  }
  if (variant === 'shield') {
    // 실드 안의 A — 기존 보안 실드 아이덴티티에 가장 근접.
    return (
      <svg {...common} strokeWidth={2}>
        <path d="M12 3l8 3.2v5.3C20 16 16.6 19.3 12 21 7.4 19.3 4 16 4 11.5V6.2z" />
        <path d="M9 15.5 12 8.5l3 7" />
        <path d="M10.2 13h3.6" />
      </svg>
    )
  }
  // beacon(기본): A 모노그램 + 스캔 라인 + 꼭짓점 비콘 노드.
  return (
    <svg {...common} strokeWidth={2.2}>
      <path d="M4.2 19.5 12 4l7.8 15.5" />
      <path d="M8 13h8" />
      <circle cx="12" cy="4" r="1.5" fill="currentColor" stroke="none" />
    </svg>
  )
}
