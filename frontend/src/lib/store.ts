/**
 * Client state.
 *
 * Only what the browser owns lives here: tab layout, focus, panel selection,
 * theme, palette visibility, toasts. Server data goes through TanStack Query, and
 * live sessions belong to the backend (ADR 0004) -- a tab holds a session *id*,
 * never the session itself, which is why closing a tab does not kill a running
 * command.
 */

import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { Protocol, SessionState } from './types'

export type Theme = 'dark' | 'light' | 'midnight' | 'contrast'

/** Per-host panels available inside a tab. */
export type PanelId = 'terminal' | 'files' | 'editor' | 'system' | 'processes' | 'services' | 'logs'

export interface Tab {
  id: string
  hostId: string
  hostName: string
  protocol: Protocol
  /** Backend session id. Empty while connecting or after a failure. */
  sessionId: string
  state: SessionState | 'pending_hostkey'
  panel: PanelId
  pinned: boolean
  /** Absolute output offset, so a reconnect asks only for the delta. */
  seq: number
  exitReason?: string
  /** Path currently open in the editor panel, if any. */
  editorPath?: string
  unread?: boolean
}

export interface Toast {
  id: string
  level: 'info' | 'success' | 'warning' | 'error'
  title: string
  message?: string
  /** Errors persist until dismissed; everything else auto-dismisses. */
  sticky?: boolean
}

interface UIState {
  theme: Theme
  terminalTheme: string
  terminalFontSize: number
  sidebarCollapsed: boolean
  sidebarWidth: number
  drawerOpen: boolean
  paletteOpen: boolean
  paletteMode: 'commands' | 'objects'
  searchQuery: string

  tabs: Tab[]
  activeTabId: string
  /** Hosts ticked for a multi-host operation. */
  selectedHostIds: string[]

  toasts: Toast[]
  /** Connection state of the notification socket, shown in the status bar. */
  eventsConnected: boolean

  setTheme: (theme: Theme) => void
  setTerminalTheme: (name: string) => void
  setTerminalFontSize: (size: number) => void
  toggleSidebar: () => void
  setSidebarWidth: (width: number) => void
  toggleDrawer: () => void
  openPalette: (mode: 'commands' | 'objects') => void
  closePalette: () => void
  setSearchQuery: (query: string) => void

  openTab: (tab: Omit<Tab, 'id' | 'pinned' | 'seq'> & Partial<Pick<Tab, 'id'>>) => string
  closeTab: (id: string) => void
  closeOtherTabs: (id: string) => void
  activateTab: (id: string) => void
  nextTab: (delta: number) => void
  updateTab: (id: string, patch: Partial<Tab>) => void
  setPanel: (id: string, panel: PanelId) => void
  togglePin: (id: string) => void
  moveTab: (from: number, to: number) => void

  toggleHostSelection: (hostId: string) => void
  clearHostSelection: () => void

  pushToast: (toast: Omit<Toast, 'id'>) => void
  dismissToast: (id: string) => void
  setEventsConnected: (connected: boolean) => void
}

let counter = 0
function nextId(prefix: string): string {
  counter += 1
  return `${prefix}-${Date.now().toString(36)}-${counter}`
}

export const useUI = create<UIState>()(
  persist(
    (set, get) => ({
      theme: 'dark',
      terminalTheme: 'axt-dark',
      terminalFontSize: 14,
      sidebarCollapsed: false,
      sidebarWidth: 260,
      drawerOpen: false,
      paletteOpen: false,
      paletteMode: 'objects',
      searchQuery: '',

      tabs: [],
      activeTabId: '',
      selectedHostIds: [],
      toasts: [],
      eventsConnected: false,

      setTheme: (theme) => {
        document.documentElement.dataset.theme = theme
        set({ theme })
      },
      setTerminalTheme: (terminalTheme) => set({ terminalTheme }),
      setTerminalFontSize: (terminalFontSize) =>
        set({ terminalFontSize: Math.min(24, Math.max(9, terminalFontSize)) }),
      toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
      setSidebarWidth: (width) => set({ sidebarWidth: Math.min(480, Math.max(180, width)) }),
      toggleDrawer: () => set((s) => ({ drawerOpen: !s.drawerOpen })),
      openPalette: (paletteMode) => set({ paletteOpen: true, paletteMode, searchQuery: '' }),
      closePalette: () => set({ paletteOpen: false, searchQuery: '' }),
      setSearchQuery: (searchQuery) => set({ searchQuery }),

      openTab: (input) => {
        const id = input.id ?? nextId('tab')
        const tab: Tab = {
          id,
          hostId: input.hostId,
          hostName: input.hostName,
          protocol: input.protocol,
          sessionId: input.sessionId,
          state: input.state,
          panel: input.panel,
          pinned: false,
          seq: 0,
        }
        set((s) => ({ tabs: [...s.tabs, tab], activeTabId: id }))
        return id
      },

      closeTab: (id) => {
        const { tabs, activeTabId } = get()
        const index = tabs.findIndex((t) => t.id === id)
        if (index === -1) return
        const remaining = tabs.filter((t) => t.id !== id)

        let nextActive = activeTabId
        if (activeTabId === id) {
          // Prefer the tab to the right, matching what editors do; fall back left.
          nextActive = remaining[index]?.id ?? remaining[index - 1]?.id ?? ''
        }
        set({ tabs: remaining, activeTabId: nextActive })
      },

      closeOtherTabs: (id) => {
        set((s) => ({
          // Pinned tabs survive "close others": pinning is the user saying keep this.
          tabs: s.tabs.filter((t) => t.id === id || t.pinned),
          activeTabId: id,
        }))
      },

      activateTab: (id) => set({ activeTabId: id }),

      nextTab: (delta) => {
        const { tabs, activeTabId } = get()
        if (tabs.length === 0) return
        const index = tabs.findIndex((t) => t.id === activeTabId)
        const next = (index + delta + tabs.length) % tabs.length
        const target = tabs[next]
        if (target) set({ activeTabId: target.id })
      },

      updateTab: (id, patch) =>
        set((s) => ({ tabs: s.tabs.map((t) => (t.id === id ? { ...t, ...patch } : t)) })),

      setPanel: (id, panel) =>
        set((s) => ({ tabs: s.tabs.map((t) => (t.id === id ? { ...t, panel } : t)) })),

      togglePin: (id) =>
        set((s) => {
          const tabs = s.tabs.map((t) => (t.id === id ? { ...t, pinned: !t.pinned } : t))
          // Pinned tabs sit left of unpinned ones, so their position is stable as
          // other tabs come and go.
          tabs.sort((a, b) => Number(b.pinned) - Number(a.pinned))
          return { tabs }
        }),

      moveTab: (from, to) =>
        set((s) => {
          const tabs = [...s.tabs]
          const [moved] = tabs.splice(from, 1)
          if (!moved) return { tabs: s.tabs }
          tabs.splice(to, 0, moved)
          return { tabs }
        }),

      toggleHostSelection: (hostId) =>
        set((s) => ({
          selectedHostIds: s.selectedHostIds.includes(hostId)
            ? s.selectedHostIds.filter((id) => id !== hostId)
            : [...s.selectedHostIds, hostId],
        })),
      clearHostSelection: () => set({ selectedHostIds: [] }),

      pushToast: (toast) => {
        const id = nextId('toast')
        const entry: Toast = { ...toast, id, sticky: toast.sticky ?? toast.level === 'error' }
        set((s) => ({ toasts: [...s.toasts, entry] }))
        if (!entry.sticky) {
          window.setTimeout(() => get().dismissToast(id), 6000)
        }
      },
      dismissToast: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
      setEventsConnected: (eventsConnected) => set({ eventsConnected }),
    }),
    {
      name: 'axt-ui',
      // Only presentation state is persisted locally. Session ids are not: a
      // reload re-reads them from the server, which is the authority on what is
      // still alive.
      partialize: (state) => ({
        theme: state.theme,
        terminalTheme: state.terminalTheme,
        terminalFontSize: state.terminalFontSize,
        sidebarCollapsed: state.sidebarCollapsed,
        sidebarWidth: state.sidebarWidth,
        drawerOpen: state.drawerOpen,
      }),
    },
  ),
)

/** Returns the active tab, or undefined. */
export function useActiveTab(): Tab | undefined {
  return useUI((s) => s.tabs.find((t) => t.id === s.activeTabId))
}

/** Applies the persisted theme before first paint. */
export function applyStoredTheme(): void {
  try {
    const raw = window.localStorage.getItem('axt-ui')
    if (!raw) return
    const parsed = JSON.parse(raw) as { state?: { theme?: Theme } }
    if (parsed.state?.theme) document.documentElement.dataset.theme = parsed.state.theme
  } catch {
    // A corrupt preference must not stop the app loading.
  }
}
