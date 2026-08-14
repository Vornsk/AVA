import { useState } from 'react'
import { Moon, Sun, ShieldCheck, ShieldOff, Lock, UserCog, User as UserIcon, LogOut, Languages } from 'lucide-react'
import { currentTheme, toggleTheme, type Theme } from '../theme'
import { usePoll, type Stats, type Me } from '../api'
import { useI18n } from '../i18n'

export function Topbar({ title, subtitle }: { title: string; subtitle?: string }) {
  const [theme, setTheme] = useState<Theme>(currentTheme())
  const { lang, setLang, t } = useI18n()
  const { data: stats } = usePoll<Stats>('/api/stats', 5000)
  const { data: me } = usePoll<Me>('/api/me', 5000)

  async function logout() {
    await fetch('/api/logout', { method: 'POST' })
    window.location.reload()
  }

  const isLeader = me?.user.role === 'leader'

  return (
    <header className="flex items-center justify-between border-b border-[var(--border)] bg-[var(--panel)] px-6 py-3.5">
      <div>
        <h1 className="text-[17px] font-bold leading-tight">{title}</h1>
        {subtitle && <p className="mt-0.5 text-xs text-[var(--muted)]">{subtitle}</p>}
      </div>
      <div className="flex items-center gap-2.5 text-xs">
        {stats && (
          <>
            <Pill icon={stats.ca_trusted ? ShieldCheck : ShieldOff}
                  text={stats.ca_trusted ? t('topbar.caTrusted') : t('topbar.caUntrusted')}
                  color={stats.ca_trusted ? 'var(--green)' : 'var(--red)'} />
            {stats.safe_mode && <Pill icon={Lock} text={t('topbar.safeMode')} color="var(--amber)" />}
          </>
        )}

        {/* 현재 사용자 (§5.1 FR-1.4) */}
        {me && (
          <span className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border)] bg-[var(--panel-2)] px-2.5 py-1.5 font-medium">
            {isLeader ? <UserCog size={14} style={{ color: 'var(--accent)' }} /> : <UserIcon size={14} />}
            {me.user.name}
            <span className="rounded px-1 py-0.5 text-[10px]"
                  style={{ color: isLeader ? 'var(--accent)' : 'var(--muted)', background: `color-mix(in srgb, ${isLeader ? 'var(--accent)' : 'var(--muted)'} 15%, transparent)` }}>
              {me.user.role}
            </span>
          </span>
        )}
        {!me?.auth_disabled && (
          <button onClick={logout} title={t('topbar.logout')}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border)] bg-[var(--panel-2)] px-2.5 py-1.5 font-medium hover:opacity-80">
            <LogOut size={14} />
          </button>
        )}

        <button onClick={() => setLang(lang === 'ko' ? 'en' : 'ko')}
                className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border)] bg-[var(--panel-2)] px-3 py-1.5 font-medium transition-opacity hover:opacity-80"
                title={t('topbar.langToggle')}>
          <Languages size={14} />
          {lang === 'ko' ? '한국어' : 'EN'}
        </button>

        <button onClick={() => setTheme(toggleTheme())}
                className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border)] bg-[var(--panel-2)] px-3 py-1.5 font-medium transition-opacity hover:opacity-80"
                title={t('topbar.themeToggle')}>
          {theme === 'dark' ? <Moon size={14} /> : <Sun size={14} />}
          {theme === 'dark' ? t('topbar.dark') : t('topbar.light')}
        </button>
      </div>
    </header>
  )
}

function Pill({ icon: Icon, text, color }: { icon: any; text: string; color: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 font-medium"
          style={{ color, background: `color-mix(in srgb, ${color} 14%, transparent)` }}>
      <Icon size={13} strokeWidth={2.2} /> {text}
    </span>
  )
}
