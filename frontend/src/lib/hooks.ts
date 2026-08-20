import { useEffect, useMemo, useRef } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { create } from 'zustand'

import { api, ApiError, items, type ListResponse } from './api'
import type {
  CreateSessionResponse,
  Credential,
  Folder,
  Host,
  HostAction,
  HostKeyPrompt,
  SessionInfo,
  SessionRecord,
  Snippet,
  SnippetFolder,
  Transfer,
} from './types'
import { EventSocket, type ServerEvent } from './ws'
import { useUI, type PanelId } from './store'

/* ------------------------------------------------------------- server data --- */

export function useHosts(query = '') {
  return useQuery({
    queryKey: ['hosts', query],
    queryFn: () =>
      api.get<ListResponse<Host>>(`/api/v1/hosts${query ? `?q=${encodeURIComponent(query)}` : ''}`),
    select: items,
  })
}

export function useFolders() {
  return useQuery({
    queryKey: ['folders'],
    queryFn: () => api.get<ListResponse<Folder>>('/api/v1/folders'),
    select: items,
  })
}

export function useCredentials() {
  return useQuery({
    queryKey: ['credentials'],
    queryFn: () => api.get<ListResponse<Credential>>('/api/v1/credentials'),
    select: items,
  })
}

export function useSnippets(query = '') {
  return useQuery({
    queryKey: ['snippets', query],
    queryFn: () =>
      api.get<ListResponse<Snippet>>(
        `/api/v1/snippets${query ? `?q=${encodeURIComponent(query)}` : ''}`,
      ),
    select: items,
  })
}

export function useSnippetFolders() {
  return useQuery({
    queryKey: ['snippet-folders'],
    queryFn: () => api.get<ListResponse<SnippetFolder>>('/api/v1/snippet-folders'),
    select: items,
  })
}

export function useRecentSessions() {
  return useQuery({
    queryKey: ['recent-sessions'],
    queryFn: () => api.get<ListResponse<SessionRecord>>('/api/v1/sessions/recent?limit=12'),
    select: items,
  })
}

export function useLiveSessions() {
  return useQuery({
    queryKey: ['sessions'],
    queryFn: () => api.get<ListResponse<SessionInfo>>('/api/v1/sessions'),
    select: items,
  })
}

export function useTransfers() {
  return useQuery({
    queryKey: ['transfers'],
    queryFn: () => api.get<ListResponse<Transfer>>('/api/v1/transfers?limit=50'),
    select: items,
  })
}

export function useHostActions(hostId: string | undefined) {
  return useQuery({
    queryKey: ['host-actions', hostId],
    queryFn: () => api.get<ListResponse<HostAction>>(`/api/v1/hosts/${hostId}/actions`),
    select: items,
    enabled: Boolean(hostId),
  })
}

/* ---------------------------------------------------------- host key prompt --- */

interface HostKeyPromptState {
  prompt: (HostKeyPrompt & { hostId: string; hostName: string }) | null
  show: (value: HostKeyPrompt & { hostId: string; hostName: string }) => void
  clear: () => void
}

/**
 * The trust-on-first-use prompt.
 *
 * A separate store because it can be raised from anywhere a connection is
 * attempted -- the tree, the palette, a recent-session row -- and must render once,
 * modally, wherever it came from.
 */
export const useHostKeyPrompt = create<HostKeyPromptState>((set) => ({
  prompt: null,
  show: (prompt) => set({ prompt }),
  clear: () => set({ prompt: null }),
}))

/* ------------------------------------------------------------ open session --- */

interface OpenSessionInput {
  host: Host
  panel?: PanelId
  /** Reuse an existing tab rather than opening another. */
  tabId?: string
}

/**
 * Opens a session and a tab for it.
 *
 * The interesting path is the host key. When the server has never seen the host's
 * key it answers with state "pending_hostkey" rather than failing, and this hook
 * raises the fingerprint prompt. Accepting it retries the connection; the
 * fingerprint that gets trusted is the one the *server* saw, never one the client
 * supplied.
 */
export function useOpenSession() {
  const openTab = useUI((s) => s.openTab)
  const updateTab = useUI((s) => s.updateTab)
  const pushToast = useUI((s) => s.pushToast)
  const showPrompt = useHostKeyPrompt((s) => s.show)
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async ({ host, panel = 'terminal', tabId }: OpenSessionInput) => {
      const id =
        tabId ??
        openTab({
          hostId: host.id,
          hostName: host.name,
          protocol: host.protocol,
          sessionId: '',
          state: 'connecting',
          panel,
        })

      try {
        const response = await api.post<CreateSessionResponse>('/api/v1/sessions', {
          host_id: host.id,
          cols: 80,
          rows: 24,
        })

        if (response.state === 'pending_hostkey' && response.pending_hostkey) {
          updateTab(id, { state: 'pending_hostkey' })
          showPrompt({ ...response.pending_hostkey, hostId: host.id, hostName: host.name })
          return { tabId: id, pending: true }
        }

        updateTab(id, {
          sessionId: response.session_id ?? '',
          state: 'connected',
          seq: 0,
          exitReason: undefined,
        })
        void queryClient.invalidateQueries({ queryKey: ['recent-sessions'] })
        void queryClient.invalidateQueries({ queryKey: ['sessions'] })
        return { tabId: id, pending: false }
      } catch (error) {
        const message = error instanceof ApiError ? error.message : 'Connection failed'
        updateTab(id, { state: 'failed', exitReason: message })

        if (error instanceof ApiError && error.code === 'hostkey_mismatch') {
          // Deliberately sticky and severe: a changed host key is either a rebuild
          // or an interception, and the two are indistinguishable from here.
          pushToast({
            level: 'error',
            title: `Host key mismatch on ${host.name}`,
            message: error.message,
            sticky: true,
          })
        } else {
          pushToast({ level: 'error', title: `Could not connect to ${host.name}`, message })
        }
        throw error
      }
    },
  })
}

/** Trusts a pending host key and retries the connection. */
export function useTrustHostKey() {
  const clear = useHostKeyPrompt((s) => s.clear)
  const pushToast = useUI((s) => s.pushToast)
  const openSession = useOpenSession()
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async ({
      hostId,
      fingerprint,
      host,
    }: {
      hostId: string
      fingerprint: string
      host: Host
    }) => {
      await api.post('/api/v1/host-keys/trust', { host_id: hostId, fingerprint })
      clear()
      void queryClient.invalidateQueries({ queryKey: ['host-keys'] })
      await openSession.mutateAsync({ host })
    },
    onError: (error) => {
      pushToast({
        level: 'error',
        title: 'Could not trust the host key',
        message: error instanceof ApiError ? error.message : 'Unexpected error',
      })
    },
  })
}

/* ------------------------------------------------------------ event stream --- */

/**
 * Connects the notification socket and routes what arrives.
 *
 * Connection *state* deliberately does not produce toasts: it lives in the tab
 * indicator and the status bar, so a flapping link does not generate a stream of
 * popups.
 */
export function useEventStream() {
  const queryClient = useQueryClient()
  const pushToast = useUI((s) => s.pushToast)
  const setEventsConnected = useUI((s) => s.setEventsConnected)
  const socketRef = useRef<EventSocket | null>(null)

  useEffect(() => {
    const socket = new EventSocket()
    socketRef.current = socket

    const off = socket.on((event: ServerEvent) => {
      switch (event.t) {
        case 'transfer.progress':
          // Progress is high-frequency; the drawer reads it from the cache rather
          // than each event triggering a refetch.
          queryClient.setQueryData(['transfers'], (old: ListResponse<Transfer> | undefined) => {
            if (!old) return old
            return {
              ...old,
              items: old.items.map((t) =>
                t.id === event.id
                  ? {
                      ...t,
                      transferred_bytes: Number(event.transferred_bytes ?? t.transferred_bytes),
                      speed_bps: Number(event.speed_bps ?? t.speed_bps),
                    }
                  : t,
              ),
            }
          })
          break

        case 'transfer.done':
          void queryClient.invalidateQueries({ queryKey: ['transfers'] })
          if (event.status === 'failed') {
            pushToast({ level: 'error', title: 'Transfer failed', message: String(event.error ?? '') })
          }
          break

        case 'host.health':
          void queryClient.invalidateQueries({ queryKey: ['hosts'] })
          break

        case 'session.state':
          void queryClient.invalidateQueries({ queryKey: ['sessions'] })
          break

        case 'notification':
          pushToast({
            level: (event.level as 'info' | 'success' | 'warning' | 'error') ?? 'info',
            title: String(event.title ?? 'Notice'),
            message: event.message ? String(event.message) : undefined,
          })
          break

        case 'server.shutdown':
          // Distinguishing a planned restart from a network failure is the whole
          // point of announcing it before the sockets go away.
          pushToast({
            level: 'warning',
            title: 'The server is restarting',
            message: 'Sessions will reconnect automatically once it is back.',
            sticky: true,
          })
          break

        default:
          break
      }
    })

    void socket.connect().then(() => setEventsConnected(true))

    return () => {
      off()
      socket.close()
      setEventsConnected(false)
    }
  }, [queryClient, pushToast, setEventsConnected])
}

/* ------------------------------------------------------------- keybindings --- */

interface CommandContext {
  openPalette: (mode: 'commands' | 'objects') => void
  toggleSidebar: () => void
  toggleDrawer: () => void
  nextTab: (delta: number) => void
  closeActiveTab: () => void
  activateIndex: (index: number) => void
}

/**
 * Global keyboard shortcuts.
 *
 * Application shortcuts use a Ctrl+Shift prefix so they cannot shadow terminal
 * control keys. Ctrl+W in particular must reach the shell as word-erase rather
 * than closing a tab -- losing a session because you tried to delete a word would
 * be unforgivable in a terminal.
 */
export function useKeybindings(context: CommandContext) {
  const ctx = useRef(context)
  ctx.current = context

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const meta = event.ctrlKey || event.metaKey
      if (!meta) return

      // Alt+1..9 jumps to a tab; handled separately because it needs no Ctrl.
      const key = event.key.toLowerCase()

      if (meta && event.shiftKey && key === 'p') {
        event.preventDefault()
        ctx.current.openPalette('commands')
        return
      }
      if (meta && !event.shiftKey && key === 'k') {
        event.preventDefault()
        ctx.current.openPalette('objects')
        return
      }
      if (meta && !event.shiftKey && key === 'b') {
        event.preventDefault()
        ctx.current.toggleSidebar()
        return
      }
      if (meta && !event.shiftKey && key === 'j') {
        event.preventDefault()
        ctx.current.toggleDrawer()
        return
      }
      if (meta && key === 'tab') {
        event.preventDefault()
        ctx.current.nextTab(event.shiftKey ? -1 : 1)
        return
      }
      if (meta && event.shiftKey && key === 'w') {
        event.preventDefault()
        ctx.current.closeActiveTab()
      }
    }

    const onAltDigit = (event: KeyboardEvent) => {
      if (!event.altKey || event.ctrlKey || event.metaKey) return
      const digit = Number(event.key)
      if (!Number.isInteger(digit) || digit < 1 || digit > 9) return
      event.preventDefault()
      ctx.current.activateIndex(digit - 1)
    }

    window.addEventListener('keydown', onKeyDown)
    window.addEventListener('keydown', onAltDigit)
    return () => {
      window.removeEventListener('keydown', onKeyDown)
      window.removeEventListener('keydown', onAltDigit)
    }
  }, [])
}

/* ----------------------------------------------------------------- helpers --- */

/** Builds the folder tree from the flat list the API returns. */
export interface FolderNode {
  folder: Folder
  children: FolderNode[]
  hosts: Host[]
}

export function useHostTree(hosts: Host[], folders: Folder[]) {
  return useMemo(() => {
    const byParent = new Map<string, Folder[]>()
    for (const folder of folders) {
      const list = byParent.get(folder.parent_id) ?? []
      list.push(folder)
      byParent.set(folder.parent_id, list)
    }

    const hostsByFolder = new Map<string, Host[]>()
    for (const host of hosts) {
      const list = hostsByFolder.get(host.folder_id) ?? []
      list.push(host)
      hostsByFolder.set(host.folder_id, list)
    }

    const build = (parentId: string): FolderNode[] =>
      (byParent.get(parentId) ?? []).map((folder) => ({
        folder,
        children: build(folder.id),
        hosts: hostsByFolder.get(folder.id) ?? [],
      }))

    return {
      roots: build(''),
      // Hosts with no folder render at the top level rather than disappearing,
      // which is what happens when a folder is deleted with the orphan strategy.
      unfiled: hostsByFolder.get('') ?? [],
      favorites: hosts.filter((h) => h.is_favorite),
    }
  }, [hosts, folders])
}
