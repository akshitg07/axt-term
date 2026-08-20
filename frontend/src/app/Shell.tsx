import { useState } from 'react'
import {
  Command,
  Files,
  Gauge,
  Layers,
  Monitor,
  MoreVertical,
  PanelLeftClose,
  PanelLeftOpen,
  Pin,
  PinOff,
  Plus,
  RefreshCw,
  Search,
  Settings,
  Terminal as TerminalIcon,
  X,
} from 'lucide-react'
import clsx from 'clsx'

import type { MeResponse } from '@/lib/types'
import { useActiveTab, useUI, type PanelId, type Tab } from '@/lib/store'
import { useHosts, useKeybindings, useOpenSession, useTransfers } from '@/lib/hooks'
import { Badge, ComingSoon, EmptyState, IconButton, Kbd, StatusDot } from '@/components/ui'
import { Wordmark } from '@/components/Wordmark'
import { Sidebar } from '@/features/hosts/Sidebar'
import { HostDialog } from '@/features/hosts/HostDialog'
import { HostKeyDialog } from '@/features/hosts/HostKeyDialog'
import { CommandPalette } from '@/features/palette/CommandPalette'
import { TerminalPane } from '@/features/terminal/TerminalPane'
import { CredentialsPanel } from '@/features/credentials/CredentialsPanel'
import { SnippetsPanel } from '@/features/snippets/SnippetsPanel'
import { SettingsPanel } from '@/features/settings/SettingsPanel'
import { TransfersDrawer } from '@/features/transfers/TransfersDrawer'

type Overlay = 'none' | 'credentials' | 'snippets' | 'settings'

/**
 * The workspace shell.
 *
 * Five regions, each with one job: top bar, sidebar, tab strip, session area, and
 * status bar, with a drawer for cross-host activity. The drawer is deliberately
 * separate from the per-host context tabs -- context tabs are *about this host*,
 * the drawer is *about everything I have running*, and conflating them is how file
 * transfers get lost in other tools.
 */
export function Shell({ me }: { me: MeResponse }) {
  const sidebarCollapsed = useUI((s) => s.sidebarCollapsed)
  const sidebarWidth = useUI((s) => s.sidebarWidth)
  const drawerOpen = useUI((s) => s.drawerOpen)
  const toggleSidebar = useUI((s) => s.toggleSidebar)
  const toggleDrawer = useUI((s) => s.toggleDrawer)
  const openPalette = useUI((s) => s.openPalette)
  const tabs = useUI((s) => s.tabs)
  const activeTabId = useUI((s) => s.activeTabId)
  const closeTab = useUI((s) => s.closeTab)
  const nextTab = useUI((s) => s.nextTab)
  const activateTab = useUI((s) => s.activateTab)

  const [overlay, setOverlay] = useState<Overlay>('none')
  const [hostDialogOpen, setHostDialogOpen] = useState(false)
  const [editingHostId, setEditingHostId] = useState<string | null>(null)

  useKeybindings({
    openPalette,
    toggleSidebar,
    toggleDrawer,
    nextTab,
    closeActiveTab: () => activeTabId && closeTab(activeTabId),
    activateIndex: (index) => {
      const target = tabs[index]
      if (target) activateTab(target.id)
    },
  })

  return (
    <div className="flex h-full flex-col overflow-hidden bg-surface-0">
      <TopBar
        me={me}
        onNewHost={() => {
          setEditingHostId(null)
          setHostDialogOpen(true)
        }}
        onOpenSettings={() => setOverlay('settings')}
      />

      <div className="flex min-h-0 flex-1">
        {!sidebarCollapsed && (
          <aside
            className="shrink-0 border-r border-border-subtle"
            style={{ width: sidebarWidth }}
            aria-label="Connections"
          >
            <Sidebar
              onNewHost={() => {
                setEditingHostId(null)
                setHostDialogOpen(true)
              }}
              onOpenCredentials={() => setOverlay('credentials')}
              onOpenSnippets={() => setOverlay('snippets')}
            />
          </aside>
        )}

        <main className="flex min-w-0 flex-1 flex-col">
          <TabStrip
            onNewTab={() => openPalette('objects')}
            onEditHost={(hostId) => {
              setEditingHostId(hostId)
              setHostDialogOpen(true)
            }}
          />
          <div className="min-h-0 flex-1">
            <SessionArea />
          </div>
          {drawerOpen && (
            <div className="h-1/4 min-h-[140px] shrink-0 border-t border-border-subtle">
              <TransfersDrawer />
            </div>
          )}
          <StatusBar me={me} />
        </main>
      </div>

      <CommandPalette
        onOpenCredentials={() => setOverlay('credentials')}
        onOpenSnippets={() => setOverlay('snippets')}
        onOpenSettings={() => setOverlay('settings')}
        onNewHost={() => {
          setEditingHostId(null)
          setHostDialogOpen(true)
        }}
      />

      <HostKeyDialog />

      <HostDialog
        open={hostDialogOpen}
        hostId={editingHostId}
        onClose={() => setHostDialogOpen(false)}
      />

      <CredentialsPanel open={overlay === 'credentials'} onClose={() => setOverlay('none')} />
      <SnippetsPanel open={overlay === 'snippets'} onClose={() => setOverlay('none')} />
      <SettingsPanel open={overlay === 'settings'} onClose={() => setOverlay('none')} me={me} />
    </div>
  )
}

/* ------------------------------------------------------------------ top bar --- */

function TopBar({
  me,
  onNewHost,
  onOpenSettings,
}: {
  me: MeResponse
  onNewHost: () => void
  onOpenSettings: () => void
}) {
  const sidebarCollapsed = useUI((s) => s.sidebarCollapsed)
  const toggleSidebar = useUI((s) => s.toggleSidebar)
  const openPalette = useUI((s) => s.openPalette)

  return (
    <header className="flex h-bar shrink-0 items-center gap-2 border-b border-border-subtle bg-surface-1 px-2">
      <IconButton
        label={sidebarCollapsed ? 'Show sidebar' : 'Hide sidebar'}
        onClick={toggleSidebar}
      >
        {sidebarCollapsed ? (
          <PanelLeftOpen className="h-4 w-4" />
        ) : (
          <PanelLeftClose className="h-4 w-4" />
        )}
      </IconButton>

      <Wordmark className="h-5" />

      {/* Search is a button rather than an input: it opens the palette, which is
          the same surface the keyboard shortcut reaches, so there is one search
          rather than two that behave differently. */}
      <button
        onClick={() => openPalette('objects')}
        className="mx-2 flex h-6 min-w-0 max-w-md flex-1 items-center gap-2 rounded border border-border-subtle bg-surface-2 px-2 text-left text-text-muted transition-colors hover:border-border-strong"
      >
        <Search className="h-3.5 w-3.5 shrink-0" aria-hidden />
        <span className="truncate text-sm">Search hosts, snippets, commands…</span>
        <Kbd>⌃K</Kbd>
      </button>

      <div className="ml-auto flex items-center gap-1">
        <button
          onClick={onNewHost}
          className="inline-flex h-6 items-center gap-1 rounded border border-border-subtle bg-surface-2 px-2 text-sm text-text-secondary hover:text-text-primary"
        >
          <Plus className="h-3.5 w-3.5" aria-hidden />
          New
        </button>
        <IconButton label="Command palette" onClick={() => openPalette('commands')}>
          <Command className="h-4 w-4" />
        </IconButton>
        <IconButton label="Settings" onClick={onOpenSettings}>
          <Settings className="h-4 w-4" />
        </IconButton>
        <span
          className="ml-1 flex h-6 items-center rounded bg-surface-2 px-2 text-sm text-text-secondary"
          title={`Signed in as ${me.user.username}`}
        >
          {me.user.display_name || me.user.username}
        </span>
      </div>
    </header>
  )
}

/* ---------------------------------------------------------------- tab strip --- */

function TabStrip({
  onNewTab,
  onEditHost,
}: {
  onNewTab: () => void
  onEditHost: (hostId: string) => void
}) {
  const tabs = useUI((s) => s.tabs)
  const activeTabId = useUI((s) => s.activeTabId)
  const activateTab = useUI((s) => s.activateTab)
  const closeTab = useUI((s) => s.closeTab)
  const togglePin = useUI((s) => s.togglePin)
  const closeOthers = useUI((s) => s.closeOtherTabs)
  const [menuFor, setMenuFor] = useState<string | null>(null)

  const hostsQuery = useHosts()
  const openSession = useOpenSession()

  const reconnect = (tab: Tab) => {
    const host = hostsQuery.data?.find((h) => h.id === tab.hostId)
    if (host) openSession.mutate({ host, tabId: tab.id })
  }

  return (
    <div className="flex h-tab shrink-0 items-stretch border-b border-border-subtle bg-surface-1">
      <div className="flex min-w-0 flex-1 items-stretch overflow-x-auto" role="tablist">
        {tabs.map((tab) => (
          <div
            key={tab.id}
            className={clsx(
              'group relative flex min-w-0 items-center gap-1.5 border-r border-border-subtle px-2.5',
              tab.id === activeTabId
                ? 'bg-surface-0 text-text-primary'
                : 'text-text-secondary hover:bg-surface-2',
            )}
            style={{ maxWidth: tab.pinned ? 120 : 220 }}
          >
            {tab.id === activeTabId && (
              <span className="absolute inset-x-0 top-0 h-0.5 bg-accent" aria-hidden />
            )}
            <button
              role="tab"
              aria-selected={tab.id === activeTabId}
              onClick={() => activateTab(tab.id)}
              className="flex min-w-0 items-center gap-1.5"
              title={`${tab.hostName} — ${tab.state}`}
            >
              <TabStateDot tab={tab} />
              {tab.protocol === 'rdp' ? (
                <Monitor className="h-3 w-3 shrink-0 text-text-muted" aria-hidden />
              ) : (
                <TerminalIcon className="h-3 w-3 shrink-0 text-text-muted" aria-hidden />
              )}
              {!tab.pinned && <span className="truncate text-base">{tab.hostName}</span>}
            </button>

            <button
              onClick={() => setMenuFor(menuFor === tab.id ? null : tab.id)}
              aria-label="Tab menu"
              className="opacity-0 transition-opacity group-hover:opacity-100"
            >
              <MoreVertical className="h-3 w-3" />
            </button>
            <button
              onClick={() => closeTab(tab.id)}
              aria-label={`Close ${tab.hostName}`}
              className="opacity-0 transition-opacity group-hover:opacity-100"
            >
              <X className="h-3 w-3" />
            </button>

            {menuFor === tab.id && (
              <div
                className="absolute left-0 top-full z-30 mt-px w-48 rounded border border-border-strong bg-surface-3 py-1"
                style={{ boxShadow: 'var(--shadow)' }}
                onMouseLeave={() => setMenuFor(null)}
              >
                <MenuItem
                  icon={<RefreshCw className="h-3.5 w-3.5" />}
                  label="Reconnect"
                  onClick={() => {
                    reconnect(tab)
                    setMenuFor(null)
                  }}
                />
                <MenuItem
                  icon={tab.pinned ? <PinOff className="h-3.5 w-3.5" /> : <Pin className="h-3.5 w-3.5" />}
                  label={tab.pinned ? 'Unpin' : 'Pin'}
                  onClick={() => {
                    togglePin(tab.id)
                    setMenuFor(null)
                  }}
                />
                <MenuItem
                  icon={<Settings className="h-3.5 w-3.5" />}
                  label="Edit host"
                  onClick={() => {
                    onEditHost(tab.hostId)
                    setMenuFor(null)
                  }}
                />
                <MenuItem
                  icon={<Layers className="h-3.5 w-3.5" />}
                  label="Close other tabs"
                  onClick={() => {
                    closeOthers(tab.id)
                    setMenuFor(null)
                  }}
                />
              </div>
            )}
          </div>
        ))}

        <IconButton label="New session" onClick={onNewTab} className="mx-1 self-center">
          <Plus className="h-3.5 w-3.5" />
        </IconButton>
      </div>
    </div>
  )
}

function MenuItem({
  icon,
  label,
  onClick,
}: {
  icon: React.ReactNode
  label: string
  onClick: () => void
}) {
  return (
    <button
      onClick={onClick}
      className="flex w-full items-center gap-2 px-2.5 py-1.5 text-left text-base text-text-secondary hover:bg-surface-2 hover:text-text-primary"
    >
      {icon}
      {label}
    </button>
  )
}

/**
 * Tab state indicator.
 *
 * The four states are visually distinct because the difference matters: a hollow
 * dot means the session is alive on the server with no browser attached, while a
 * crossed dot means it is dead and its content is frozen history.
 */
function TabStateDot({ tab }: { tab: Tab }) {
  switch (tab.state) {
    case 'connected':
      return <StatusDot status="online" />
    case 'connecting':
    case 'pending_hostkey':
      return <StatusDot status="connecting" />
    case 'detached':
      return <StatusDot status="unknown" />
    case 'failed':
      return <StatusDot status="error" />
    default:
      return <StatusDot status="offline" />
  }
}

/* -------------------------------------------------------------- session area --- */

const PANELS: { id: PanelId; label: string; icon: React.ReactNode; phase?: string }[] = [
  { id: 'terminal', label: 'Terminal', icon: <TerminalIcon className="h-3.5 w-3.5" /> },
  { id: 'files', label: 'Files', icon: <Files className="h-3.5 w-3.5" />, phase: 'phase-1' },
  { id: 'system', label: 'System', icon: <Gauge className="h-3.5 w-3.5" />, phase: 'phase-1' },
  { id: 'processes', label: 'Processes', icon: <Layers className="h-3.5 w-3.5" />, phase: 'phase-2' },
  { id: 'services', label: 'Services', icon: <Settings className="h-3.5 w-3.5" />, phase: 'phase-2' },
  { id: 'logs', label: 'Logs', icon: <Files className="h-3.5 w-3.5" />, phase: 'phase-3' },
]

function SessionArea() {
  const tab = useActiveTab()
  const setPanel = useUI((s) => s.setPanel)
  const openPalette = useUI((s) => s.openPalette)

  if (!tab) {
    return (
      <div className="flex h-full items-center justify-center">
        <EmptyState
          icon={<TerminalIcon className="h-7 w-7" />}
          title="No session open"
          message="Press Ctrl+K and type a few characters of a host name to connect."
          action={
            <button
              onClick={() => openPalette('objects')}
              className="mt-2 inline-flex h-7 items-center gap-1.5 rounded border border-border-subtle bg-surface-2 px-3 text-base text-text-primary hover:bg-surface-3"
            >
              <Search className="h-3.5 w-3.5" aria-hidden />
              Quick connect
              <Kbd>⌃K</Kbd>
            </button>
          }
        />
      </div>
    )
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="min-h-0 flex-1">
        {tab.panel === 'terminal' ? (
          tab.sessionId ? (
            <TerminalPane tab={tab} />
          ) : (
            <div className="flex h-full items-center justify-center">
              <EmptyState
                title={tab.state === 'failed' ? 'Connection failed' : 'Connecting…'}
                message={tab.exitReason}
              />
            </div>
          )
        ) : (
          <ComingSoon
            feature={PANELS.find((p) => p.id === tab.panel)?.label ?? 'Panel'}
            phase={PANELS.find((p) => p.id === tab.panel)?.phase}
            description={`This panel will operate on ${tab.hostName} over the same SSH connection the terminal is already using.`}
          />
        )}
      </div>

      {/* Context tabs: about *this host*, as opposed to the drawer below, which is
          about everything running. */}
      <div className="flex h-7 shrink-0 items-stretch gap-px border-t border-border-subtle bg-surface-1 px-1">
        {PANELS.map((panel) => (
          <button
            key={panel.id}
            onClick={() => setPanel(tab.id, panel.id)}
            className={clsx(
              'flex items-center gap-1.5 rounded-t px-2.5 text-sm transition-colors',
              tab.panel === panel.id
                ? 'bg-surface-0 text-text-primary'
                : 'text-text-secondary hover:bg-surface-2 hover:text-text-primary',
            )}
          >
            {panel.icon}
            {panel.label}
            {panel.phase && panel.phase !== 'phase-1' && (
              <span className="text-xs text-text-muted">soon</span>
            )}
          </button>
        ))}
      </div>
    </div>
  )
}

/* -------------------------------------------------------------- status bar --- */

function StatusBar({ me }: { me: MeResponse }) {
  const tab = useActiveTab()
  const tabs = useUI((s) => s.tabs)
  const drawerOpen = useUI((s) => s.drawerOpen)
  const toggleDrawer = useUI((s) => s.toggleDrawer)
  const eventsConnected = useUI((s) => s.eventsConnected)
  const selected = useUI((s) => s.selectedHostIds)
  const transfers = useTransfers()

  const active = (transfers.data ?? []).filter((t) => t.status === 'active').length

  return (
    <footer className="flex h-status shrink-0 items-center gap-3 border-t border-border-subtle bg-surface-1 px-2 text-sm text-text-secondary">
      {tab ? (
        <>
          <span className="flex items-center gap-1.5">
            <TabStateDot tab={tab} />
            <span className="text-text-primary">{tab.hostName}</span>
          </span>
          <span className="text-text-muted">{tab.protocol}</span>
          {tab.exitReason && <span className="truncate text-text-muted">{tab.exitReason}</span>}
        </>
      ) : (
        <span className="text-text-muted">Not connected</span>
      )}

      <div className="ml-auto flex items-center gap-3">
        {selected.length > 0 && <Badge tone="accent">{selected.length} hosts selected</Badge>}

        <button
          onClick={toggleDrawer}
          className="flex items-center gap-1.5 hover:text-text-primary"
          aria-pressed={drawerOpen}
        >
          <Files className="h-3.5 w-3.5" aria-hidden />
          Transfers
          {active > 0 && <Badge tone="accent">{active}</Badge>}
        </button>

        <span className="text-text-muted">{tabs.length} sessions</span>

        <span
          className="flex items-center gap-1.5"
          title={eventsConnected ? 'Live updates connected' : 'Live updates disconnected'}
        >
          <StatusDot status={eventsConnected ? 'online' : 'offline'} />
          {eventsConnected ? 'live' : 'offline'}
        </span>

        {!me.rdp_enabled && (
          <span className="text-text-muted" title="AXT_GUACD_ADDR is not configured">
            RDP off
          </span>
        )}
      </div>
    </footer>
  )
}
