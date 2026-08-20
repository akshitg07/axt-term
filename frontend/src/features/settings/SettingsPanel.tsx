import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Monitor, Palette, ShieldCheck, Type } from 'lucide-react'

import { api } from '@/lib/api'
import type { MeResponse } from '@/lib/types'
import { useUI, type Theme } from '@/lib/store'
import { Badge, Button, Dialog, Select } from '@/components/ui'
import { terminalThemes } from '@/features/terminal/themes'

const THEMES: { id: Theme; label: string; note: string }[] = [
  { id: 'dark', label: 'Dark', note: 'Default' },
  { id: 'light', label: 'Light', note: '' },
  { id: 'midnight', label: 'Midnight', note: 'Near-black, for OLED' },
  { id: 'contrast', label: 'High contrast', note: 'WCAG AAA, no reliance on hue' },
]

export function SettingsPanel({
  open,
  onClose,
  me,
}: {
  open: boolean
  onClose: () => void
  me: MeResponse
}) {
  const theme = useUI((s) => s.theme)
  const setTheme = useUI((s) => s.setTheme)
  const terminalTheme = useUI((s) => s.terminalTheme)
  const setTerminalTheme = useUI((s) => s.setTerminalTheme)
  const fontSize = useUI((s) => s.terminalFontSize)
  const setFontSize = useUI((s) => s.setTerminalFontSize)
  const queryClient = useQueryClient()

  // Preferences follow the user across browsers, so they are stored server-side
  // as well as locally.
  const persist = useMutation({
    mutationFn: (values: Record<string, unknown>) => api.put('/api/v1/me/settings', values),
  })

  const logout = useMutation({
    mutationFn: () => api.post('/api/v1/auth/logout'),
    onSuccess: () => {
      queryClient.setQueryData(['me'], null)
      queryClient.clear()
    },
  })

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Settings"
      description={`Signed in as ${me.user.username} · ${me.user.roles.join(', ')}`}
      width="lg"
      footer={
        <>
          <Button variant="danger" loading={logout.isPending} onClick={() => logout.mutate()}>
            Sign out
          </Button>
          <Button variant="ghost" onClick={onClose}>
            Close
          </Button>
        </>
      }
    >
      <div className="space-y-5">
        <section>
          <h3 className="mb-2 flex items-center gap-1.5 text-base text-text-primary">
            <Palette className="h-3.5 w-3.5 text-text-muted" aria-hidden />
            Appearance
          </h3>
          <div className="grid grid-cols-2 gap-2">
            {THEMES.map((entry) => (
              <button
                key={entry.id}
                onClick={() => {
                  setTheme(entry.id)
                  persist.mutate({ 'ui.theme': entry.id })
                }}
                className={`rounded border px-2.5 py-2 text-left transition-colors ${
                  theme === entry.id
                    ? 'border-accent bg-accent-muted/20'
                    : 'border-border-subtle hover:bg-surface-2'
                }`}
              >
                <span className="block text-base text-text-primary">{entry.label}</span>
                {entry.note && <span className="block text-sm text-text-muted">{entry.note}</span>}
              </button>
            ))}
          </div>
        </section>

        <section>
          <h3 className="mb-2 flex items-center gap-1.5 text-base text-text-primary">
            <Type className="h-3.5 w-3.5 text-text-muted" aria-hidden />
            Terminal
          </h3>
          <div className="grid grid-cols-2 gap-3">
            <Select
              label="Colour scheme"
              value={terminalTheme}
              onChange={(event) => {
                setTerminalTheme(event.target.value)
                persist.mutate({ 'terminal.theme': event.target.value })
              }}
            >
              {terminalThemes.map((entry) => (
                <option key={entry.id} value={entry.id}>
                  {entry.label}
                </option>
              ))}
            </Select>
            <Select
              label="Font size"
              value={String(fontSize)}
              onChange={(event) => {
                const size = Number(event.target.value)
                setFontSize(size)
                persist.mutate({ 'terminal.font_size': size })
              }}
            >
              {[10, 11, 12, 13, 14, 15, 16, 18, 20].map((size) => (
                <option key={size} value={size}>
                  {size}px
                </option>
              ))}
            </Select>
          </div>
          <p className="hint">
            The terminal scheme is independent of the interface theme, so a dark
            terminal in a light interface is a valid choice.
          </p>
        </section>

        <section>
          <h3 className="mb-2 flex items-center gap-1.5 text-base text-text-primary">
            <Monitor className="h-3.5 w-3.5 text-text-muted" aria-hidden />
            Keyboard
          </h3>
          <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
            {[
              ['Ctrl+K', 'Quick connect'],
              ['Ctrl+Shift+P', 'Command palette'],
              ['Ctrl+B', 'Toggle sidebar'],
              ['Ctrl+J', 'Toggle transfers drawer'],
              ['Ctrl+Tab', 'Next session'],
              ['Ctrl+Shift+W', 'Close session'],
              ['Alt+1…9', 'Jump to session'],
              ['Ctrl+F', 'Search in terminal'],
            ].map(([keys, action]) => (
              <div key={keys} className="flex items-center justify-between gap-2">
                <dt className="text-text-secondary">{action}</dt>
                <dd className="kbd">{keys}</dd>
              </div>
            ))}
          </dl>
          <p className="hint">
            Application shortcuts use a Ctrl+Shift prefix so they never shadow
            terminal control keys — Ctrl+W stays word-erase in the shell.
          </p>
        </section>

        <section>
          <h3 className="mb-2 flex items-center gap-1.5 text-base text-text-primary">
            <ShieldCheck className="h-3.5 w-3.5 text-text-muted" aria-hidden />
            This instance
          </h3>
          <dl className="space-y-1 text-sm">
            <div className="flex justify-between gap-2">
              <dt className="text-text-secondary">Address</dt>
              <dd className="font-mono text-text-primary">{me.instance}</dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt className="text-text-secondary">Remote desktop</dt>
              <dd>
                {me.rdp_enabled ? (
                  <Badge tone="success">available</Badge>
                ) : (
                  <Badge>not configured</Badge>
                )}
              </dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt className="text-text-secondary">Permissions</dt>
              <dd className="text-text-primary">{me.user.permissions.length} granted</dd>
            </div>
          </dl>
        </section>
      </div>
    </Dialog>
  )
}
