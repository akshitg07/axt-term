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

/**
 * The contextual actions a host offers, as the server reports them.
 *
 * Distinct from `useHostActions` below, which is the set of *mutations* a sidebar
 * row performs. This one is a read: the server decides which actions a host
 * supports and which are still unimplemented, so the UI can label them rather
 * than guessing from the protocol.
 */
export function useHostActionList(hostId: string | undefined) {
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

/** Protocols served by the guacd bridge rather than a PTY. */
export function isDesktopProtocol(protocol: Host['protocol']): boolean {
  return protocol === 'rdp' || protocol === 'vnc'
}

/**
 * An opening size for a desktop, in pixels.
 *
 * A first guess from the viewport: the pane has not been laid out when the session
 * is created, and the RDP pane resizes to its real geometry as soon as it mounts.
 * Guessing beats sending nothing, because the first frames guacd draws are at
 * whatever size the handshake agreed.
 */
function desktopGeometry(): { width: number; height: number; dpi: number } {
  // Rough allowance for the sidebar, tab strip, toolbar, and status bar, so the
  // first paint is close to the space the pane will actually have.
  const width = Math.max(640, Math.round(window.innerWidth - 280))
  const height = Math.max(480, Math.round(window.innerHeight - 130))
  return { width, height, dpi: Math.round(96 * (window.devicePixelRatio || 1)) }
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
      const desktop = isDesktopProtocol(host.protocol)
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
          ...(desktop ? desktopGeometry() : { cols: 80, rows: 24 }),
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

/* ------------------------------------------------------- managing connections --- */

/**
 * Mutations behind the sidebar's row actions.
 *
 * Grouped in one hook because a row needs most of them at once and six separate
 * hooks per row would be six subscriptions per host, with hundreds of hosts on
 * screen.
 *
 * Every one of these invalidates rather than patching the cache: an edit can change
 * a host's folder, favourite status, and name at once, which moves the row in the
 * tree. Recomputing from the server is cheaper to be right about than replaying the
 * same reordering rules on the client.
 */
export function useHostActions() {
  const queryClient = useQueryClient()
  const pushToast = useUI((s) => s.pushToast)

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ['hosts'] })
    void queryClient.invalidateQueries({ queryKey: ['folders'] })
  }

  const report = (title: string) => (error: unknown) =>
    pushToast({
      level: 'error',
      title,
      message: error instanceof ApiError ? error.message : 'Unexpected error',
    })

  const toggleFavorite = useMutation({
    mutationFn: (host: Host) =>
      api.post(`/api/v1/hosts/${host.id}/favorite`, { is_favorite: !host.is_favorite }),
    onSuccess: refresh,
    onError: report('Could not change the favourite'),
  })

  const duplicate = useMutation({
    mutationFn: (host: Host) => api.post<Host>(`/api/v1/hosts/${host.id}/duplicate`),
    onSuccess: (created) => {
      refresh()
      pushToast({ level: 'success', title: `Duplicated as ${created.name}` })
    },
    onError: report('Could not duplicate the host'),
  })

  const remove = useMutation({
    mutationFn: (host: Host) => api.del(`/api/v1/hosts/${host.id}`),
    onSuccess: (_result, host) => {
      refresh()
      void queryClient.invalidateQueries({ queryKey: ['recent-sessions'] })
      pushToast({ level: 'success', title: `Deleted ${host.name}` })
    },
    onError: report('Could not delete the host'),
  })

  const rename = useMutation({
    // The update endpoint replaces the host from the request body rather than
    // patching named fields, so a rename sends the host it already has with one
    // value changed. Sending only {name} would blank everything else.
    mutationFn: ({ host, name }: { host: Host; name: string }) =>
      api.patch<Host>(`/api/v1/hosts/${host.id}`, {
        name,
        hostname: host.hostname,
        port: host.port,
        protocol: host.protocol,
        folder_id: host.folder_id,
        username: host.username,
        auth_method: host.auth_method,
        credential_id: host.credential_id,
        jump_host_id: host.jump_host_id,
        os_family: host.os_family,
        color: host.color,
        icon: host.icon,
        notes: host.notes,
        is_favorite: host.is_favorite,
        health_check_enabled: host.health_check_enabled,
        health_check_interval_s: host.health_check_interval_s,
        command_logging: host.command_logging,
        rdp_options: host.rdp_options,
        tags: host.tags,
      }),
    onSuccess: refresh,
    onError: report('Could not rename the host'),
  })

  return { toggleFavorite, duplicate, remove, rename }
}

/**
 * Mutations for curating the Recent list.
 *
 * This edits session *history*, which is a convenience list. The audit log is a
 * separate append-only table and is not touched, so removing a row here tidies the
 * sidebar without erasing any record of the connection.
 */
export function useRecentActions() {
  const queryClient = useQueryClient()
  const pushToast = useUI((s) => s.pushToast)

  const refresh = () => queryClient.invalidateQueries({ queryKey: ['recent-sessions'] })

  const remove = useMutation({
    mutationFn: (recordId: string) => api.del(`/api/v1/sessions/recent/${recordId}`),
    onSuccess: () => void refresh(),
    onError: (error) =>
      pushToast({
        level: 'error',
        title: 'Could not remove that entry',
        message: error instanceof ApiError ? error.message : 'Unexpected error',
      }),
  })

  const clear = useMutation({
    mutationFn: () => api.del<{ removed: number }>('/api/v1/sessions/recent'),
    onSuccess: (result) => {
      void refresh()
      pushToast({
        level: 'success',
        title: 'Recent list cleared',
        message: `${result?.removed ?? 0} entries removed. The audit log is unaffected.`,
      })
    },
    onError: (error) =>
      pushToast({
        level: 'error',
        title: 'Could not clear the list',
        message: error instanceof ApiError ? error.message : 'Unexpected error',
      }),
  })

  return { remove, clear }
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
