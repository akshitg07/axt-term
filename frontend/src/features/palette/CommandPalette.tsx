import { useEffect, useMemo, useState } from 'react'
import { Command, FolderOpen, KeyRound, Plus, Server, Settings, Terminal } from 'lucide-react'
import clsx from 'clsx'

import { useHosts, useOpenSession, useSnippets } from '@/lib/hooks'
import { useUI } from '@/lib/store'
import { fuzzyFilter } from '@/lib/format'
import { Kbd, StatusDot } from '@/components/ui'

interface PaletteProps {
  onOpenCredentials: () => void
  onOpenSnippets: () => void
  onOpenSettings: () => void
  onNewHost: () => void
}

interface Entry {
  id: string
  group: string
  label: string
  detail?: string
  icon: React.ReactNode
  run: () => void
}

/**
 * The command palette.
 *
 * Two entry points into one surface: Ctrl+K is object-first (you know the host),
 * Ctrl+Shift+P is verb-first (you know the action). Both draw from the same entry
 * list, so there is one search rather than two that behave differently.
 */
export function CommandPalette({
  onOpenCredentials,
  onOpenSnippets,
  onOpenSettings,
  onNewHost,
}: PaletteProps) {
  const open = useUI((s) => s.paletteOpen)
  const mode = useUI((s) => s.paletteMode)
  const close = useUI((s) => s.closePalette)
  const toggleSidebar = useUI((s) => s.toggleSidebar)
  const toggleDrawer = useUI((s) => s.toggleDrawer)
  const setTheme = useUI((s) => s.setTheme)
  const tabs = useUI((s) => s.tabs)
  const activateTab = useUI((s) => s.activateTab)

  const [query, setQuery] = useState('')
  const [cursor, setCursor] = useState(0)

  const hostsQuery = useHosts()
  const snippetsQuery = useSnippets()
  const openSession = useOpenSession()

  useEffect(() => {
    if (open) {
      setQuery('')
      setCursor(0)
    }
  }, [open])

  const entries = useMemo<Entry[]>(() => {
    const list: Entry[] = []

    for (const host of hostsQuery.data ?? []) {
      list.push({
        id: `host-${host.id}`,
        group: 'Hosts',
        label: host.name,
        detail: `${host.protocol} · ${host.hostname}:${host.port}${host.folder_path ? ` · ${host.folder_path}` : ''}`,
        icon: <StatusDot status={host.health?.status ?? 'unknown'} />,
        run: () => {
          openSession.mutate({ host })
          close()
        },
      })
    }

    for (const tab of tabs) {
      list.push({
        id: `tab-${tab.id}`,
        group: 'Open sessions',
        label: tab.hostName,
        detail: `switch to this tab · ${tab.state}`,
        icon: <Terminal className="h-3.5 w-3.5 text-text-muted" />,
        run: () => {
          activateTab(tab.id)
          close()
        },
      })
    }

    for (const snippet of snippetsQuery.data ?? []) {
      list.push({
        id: `snippet-${snippet.id}`,
        group: 'Snippets',
        label: snippet.name,
        detail: snippet.description || snippet.body.slice(0, 60),
        icon: <FolderOpen className="h-3.5 w-3.5 text-text-muted" />,
        run: () => {
          onOpenSnippets()
          close()
        },
      })
    }

    const commands: Entry[] = [
      {
        id: 'cmd-new-host',
        group: 'Commands',
        label: 'Add a host',
        icon: <Plus className="h-3.5 w-3.5 text-text-muted" />,
        run: () => {
          onNewHost()
          close()
        },
      },
      {
        id: 'cmd-credentials',
        group: 'Commands',
        label: 'Open credentials',
        icon: <KeyRound className="h-3.5 w-3.5 text-text-muted" />,
        run: () => {
          onOpenCredentials()
          close()
        },
      },
      {
        id: 'cmd-snippets',
        group: 'Commands',
        label: 'Open snippets',
        icon: <FolderOpen className="h-3.5 w-3.5 text-text-muted" />,
        run: () => {
          onOpenSnippets()
          close()
        },
      },
      {
        id: 'cmd-settings',
        group: 'Commands',
        label: 'Open settings',
        icon: <Settings className="h-3.5 w-3.5 text-text-muted" />,
        run: () => {
          onOpenSettings()
          close()
        },
      },
      {
        id: 'cmd-sidebar',
        group: 'Commands',
        label: 'Toggle sidebar',
        detail: 'Ctrl+B',
        icon: <Command className="h-3.5 w-3.5 text-text-muted" />,
        run: () => {
          toggleSidebar()
          close()
        },
      },
      {
        id: 'cmd-drawer',
        group: 'Commands',
        label: 'Toggle transfers drawer',
        detail: 'Ctrl+J',
        icon: <Command className="h-3.5 w-3.5 text-text-muted" />,
        run: () => {
          toggleDrawer()
          close()
        },
      },
      ...(['dark', 'light', 'midnight', 'contrast'] as const).map((theme) => ({
        id: `cmd-theme-${theme}`,
        group: 'Commands',
        label: `Theme: ${theme}`,
        icon: <Settings className="h-3.5 w-3.5 text-text-muted" />,
        run: () => {
          setTheme(theme)
          close()
        },
      })),
    ]

    // Verb-first mode puts commands ahead of objects; object-first does the
    // reverse. Same list, different ordering -- which is the whole distinction.
    return mode === 'commands' ? [...commands, ...list] : [...list, ...commands]
  }, [
    hostsQuery.data,
    snippetsQuery.data,
    tabs,
    mode,
    openSession,
    close,
    activateTab,
    onNewHost,
    onOpenCredentials,
    onOpenSnippets,
    onOpenSettings,
    toggleSidebar,
    toggleDrawer,
    setTheme,
  ])

  const results = useMemo(
    () => fuzzyFilter(entries, query, (e) => `${e.label} ${e.detail ?? ''}`).slice(0, 40),
    [entries, query],
  )

  useEffect(() => setCursor(0), [query])

  if (!open) return null

  const grouped = results.reduce<Record<string, Entry[]>>((acc, entry) => {
    const bucket = acc[entry.group] ?? []
    bucket.push(entry)
    acc[entry.group] = bucket
    return acc
  }, {})

  let flatIndex = -1

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center p-4 pt-[12vh]">
      <div className="absolute inset-0 bg-black/60 animate-fade-in" onClick={close} aria-hidden />
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        className="relative w-full max-w-xl overflow-hidden rounded-lg border border-border-strong bg-surface-3 animate-slide-up"
        style={{ boxShadow: 'var(--shadow)' }}
      >
        <div className="flex items-center gap-2 border-b border-border-subtle px-3 py-2">
          <Server className="h-4 w-4 shrink-0 text-text-muted" aria-hidden />
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'Escape') {
                event.preventDefault()
                close()
              }
              if (event.key === 'ArrowDown') {
                event.preventDefault()
                setCursor((c) => Math.min(results.length - 1, c + 1))
              }
              if (event.key === 'ArrowUp') {
                event.preventDefault()
                setCursor((c) => Math.max(0, c - 1))
              }
              if (event.key === 'Enter') {
                event.preventDefault()
                results[cursor]?.run()
              }
            }}
            placeholder={mode === 'commands' ? 'Run a command…' : 'Search hosts and sessions…'}
            aria-label="Search"
            autoFocus
            spellCheck={false}
            className="flex-1 bg-transparent text-md text-text-primary outline-none placeholder:text-text-muted"
          />
          <Kbd>esc</Kbd>
        </div>

        <div className="max-h-[55vh] overflow-y-auto py-1">
          {results.length === 0 && (
            <p className="px-3 py-6 text-center text-sm text-text-muted">No matches.</p>
          )}

          {Object.entries(grouped).map(([group, groupEntries]) => (
            <div key={group}>
              <p className="px-3 pb-0.5 pt-2 text-xs font-medium uppercase tracking-wider text-text-muted">
                {group}
              </p>
              {groupEntries.map((entry) => {
                flatIndex += 1
                const active = flatIndex === cursor
                const index = flatIndex
                return (
                  <button
                    key={entry.id}
                    onMouseEnter={() => setCursor(index)}
                    onClick={entry.run}
                    className={clsx(
                      'flex w-full items-center gap-2.5 px-3 py-1.5 text-left',
                      active ? 'bg-accent-muted/30' : 'hover:bg-surface-2',
                    )}
                  >
                    <span className="shrink-0">{entry.icon}</span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-base text-text-primary">
                        {entry.label}
                      </span>
                      {entry.detail && (
                        <span className="block truncate text-sm text-text-muted">
                          {entry.detail}
                        </span>
                      )}
                    </span>
                    {active && <Kbd>⏎</Kbd>}
                  </button>
                )
              })}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
