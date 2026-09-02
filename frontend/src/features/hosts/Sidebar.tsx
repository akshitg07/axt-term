import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import {
  ChevronDown,
  ChevronRight,
  Clock,
  Copy,
  Folder as FolderIcon,
  FolderOpen,
  KeyRound,
  Monitor,
  MoreVertical,
  Network,
  Pencil,
  Plus,
  Search,
  Server,
  Star,
  StarOff,
  Terminal as TerminalIcon,
  Trash2,
  X,
} from 'lucide-react'
import clsx from 'clsx'

import type { Host, Protocol, SessionRecord } from '@/lib/types'
import {
  isDesktopProtocol,
  useFolders,
  useHostActions,
  useHostTree,
  useHosts,
  useOpenSession,
  useRecentActions,
  useRecentSessions,
} from '@/lib/hooks'
import { useUI } from '@/lib/store'
import { EmptyState, IconButton, Spinner, StatusDot, useConfirm, type DotStatus } from '@/components/ui'
import { formatRelative, fuzzyFilter } from '@/lib/format'

/** Protocol glyphs, so SSH, RDP, and SFTP read distinctly at row size. */
function ProtocolIcon({ protocol, className }: { protocol: Protocol; className?: string }) {
  const shared = clsx('h-3.5 w-3.5 shrink-0', className)
  switch (protocol) {
    case 'rdp':
    case 'vnc':
      return <Monitor className={shared} aria-label="Remote desktop" />
    case 'telnet':
    case 'serial':
      return <Network className={shared} aria-label="Serial or telnet" />
    default:
      return <TerminalIcon className={shared} aria-label="Shell" />
  }
}

function healthStatus(host: Host): DotStatus {
  if (!host.health) return 'unknown'
  return host.health.status
}

interface SidebarProps {
  onNewHost: () => void
  onEditHost: (hostId: string) => void
  onOpenCredentials: () => void
  onOpenSnippets: () => void
}

/**
 * The connections sidebar.
 *
 * A tree with sections rather than a nav menu, because the tree is for discovery
 * and the command palette is for routine access. Filtering collapses to matches
 * with their ancestors, and Enter connects to the top hit -- so the common case is
 * three keystrokes, not a scroll.
 *
 * Rows are also where connections are *managed*: edit, duplicate, favourite,
 * rename, and delete are on the row, because having to open a session in order to
 * edit the thing that describes it is backwards.
 */
export function Sidebar({ onNewHost, onEditHost, onOpenCredentials, onOpenSnippets }: SidebarProps) {
  const [filter, setFilter] = useState('')
  const [expanded, setExpanded] = useState<Record<string, boolean>>({})
  const [showFavorites, setShowFavorites] = useState(true)
  const [showRecent, setShowRecent] = useState(true)
  /** Row whose menu is open, and where to draw it. */
  const [menu, setMenu] = useState<{ hostId: string; x: number; y: number } | null>(null)
  /** Host being renamed inline. */
  const [renamingId, setRenamingId] = useState<string | null>(null)

  const hostsQuery = useHosts()
  const foldersQuery = useFolders()
  const recentQuery = useRecentSessions()
  const openSession = useOpenSession()
  const actions = useHostActions()
  const recentActions = useRecentActions()
  const confirm = useConfirm()

  const hosts = hostsQuery.data ?? []
  const folders = foldersQuery.data ?? []

  const filteredHosts = useMemo(
    () => fuzzyFilter(hosts, filter, (h) => `${h.name} ${h.hostname} ${h.tags.join(' ')}`),
    [hosts, filter],
  )
  const tree = useHostTree(filteredHosts, folders)

  const connect = (host: Host) => openSession.mutate({ host })
  const toggle = (id: string) => setExpanded((prev) => ({ ...prev, [id]: !prev[id] }))

  const menuHost = menu ? hosts.find((h) => h.id === menu.hostId) : undefined

  const remove = async (host: Host) => {
    const ok = await confirm({
      title: `Delete ${host.name}?`,
      message: (
        <>
          <p>
            This removes {host.name} ({host.hostname}) from the inventory. Credentials it
            references are not deleted, and any session already open stays open.
          </p>
          <p className="mt-2 text-text-muted">This cannot be undone.</p>
        </>
      ),
      confirmLabel: 'Delete host',
      destructive: true,
    })
    if (ok) actions.remove.mutate(host)
  }

  const clearRecent = async () => {
    const ok = await confirm({
      title: 'Clear the Recent list?',
      message: (
        <>
          <p>This removes your session history, which is what the Recent list is built from.</p>
          <p className="mt-2 text-text-muted">
            Hosts are not affected, and the audit log keeps its own record of every connection.
          </p>
        </>
      ),
      confirmLabel: 'Clear list',
      destructive: true,
    })
    if (ok) recentActions.clear.mutate()
  }

  const rowActions: RowActions = {
    connect,
    edit: onEditHost,
    duplicate: (host) => actions.duplicate.mutate(host),
    toggleFavorite: (host) => actions.toggleFavorite.mutate(host),
    startRename: (host) => setRenamingId(host.id),
    remove,
    openMenu: (host, x, y) => setMenu({ hostId: host.id, x, y }),
  }

  return (
    <div className="flex h-full min-h-0 flex-col bg-surface-1">
      <div className="flex h-8 shrink-0 items-center gap-1 border-b border-border-subtle px-2">
        <span className="text-xs font-medium uppercase tracking-wider text-text-muted">
          Connections
        </span>
        <IconButton label="New connection" className="ml-auto" onClick={onNewHost}>
          <Plus className="h-3.5 w-3.5" />
        </IconButton>
      </div>

      <div className="shrink-0 border-b border-border-subtle p-2">
        <div className="relative">
          <Search
            className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-text-muted"
            aria-hidden
          />
          <input
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter') {
                const first = filteredHosts[0]
                if (first) connect(first)
              }
              if (event.key === 'Escape') setFilter('')
            }}
            placeholder="Filter hosts"
            aria-label="Filter hosts"
            className="field h-6 pl-7"
            spellCheck={false}
          />
        </div>
      </div>

      <nav className="min-h-0 flex-1 overflow-y-auto py-1" aria-label="Host inventory">
        {hostsQuery.isLoading && (
          <div className="flex justify-center py-6">
            <Spinner />
          </div>
        )}

        {!hostsQuery.isLoading && hosts.length === 0 && (
          <EmptyState
            icon={<Server className="h-6 w-6" />}
            title="No hosts yet"
            message="Add your first machine to get started."
          />
        )}

        {!hostsQuery.isLoading && hosts.length > 0 && filteredHosts.length === 0 && (
          <p className="px-3 py-4 text-sm text-text-muted">Nothing matches that filter.</p>
        )}

        {tree.favorites.length > 0 && (
          <Section
            label="Favorites"
            count={tree.favorites.length}
            icon={<Star className="h-3.5 w-3.5" />}
            open={showFavorites}
            onToggle={() => setShowFavorites((open) => !open)}
          >
            {tree.favorites.map((host) => (
              <HostRow
                key={`fav-${host.id}`}
                host={host}
                depth={1}
                actions={rowActions}
                renaming={renamingId === host.id}
                onRename={(name) => {
                  setRenamingId(null)
                  if (name && name !== host.name) actions.rename.mutate({ host, name })
                }}
                onCancelRename={() => setRenamingId(null)}
              />
            ))}
          </Section>
        )}

        {tree.roots.map((node) => (
          <FolderBranch
            key={node.folder.id}
            node={node}
            depth={0}
            expanded={expanded}
            // A filter is a request to see what matched, so branches open while
            // one is active.
            forceOpen={filter.length > 0}
            onToggle={toggle}
            actions={rowActions}
            renamingId={renamingId}
            onRename={(host, name) => {
              setRenamingId(null)
              if (name && name !== host.name) actions.rename.mutate({ host, name })
            }}
            onCancelRename={() => setRenamingId(null)}
          />
        ))}

        {tree.unfiled.length > 0 && (
          <div className="mt-1">
            {tree.unfiled.map((host) => (
              <HostRow
                key={host.id}
                host={host}
                depth={0}
                actions={rowActions}
                renaming={renamingId === host.id}
                onRename={(name) => {
                  setRenamingId(null)
                  if (name && name !== host.name) actions.rename.mutate({ host, name })
                }}
                onCancelRename={() => setRenamingId(null)}
              />
            ))}
          </div>
        )}
      </nav>

      <div className="shrink-0 border-t border-border-subtle">
        {(recentQuery.data?.length ?? 0) > 0 && (
          <Section
            label="Recent"
            icon={<Clock className="h-3.5 w-3.5" />}
            open={showRecent}
            onToggle={() => setShowRecent((open) => !open)}
            action={
              showRecent ? (
                <IconButton label="Clear the Recent list" onClick={clearRecent}>
                  <Trash2 className="h-3 w-3" />
                </IconButton>
              ) : undefined
            }
          >
            {(recentQuery.data ?? []).slice(0, 6).map((record) => (
              <RecentRow
                key={record.id}
                record={record}
                host={hosts.find((h) => h.id === record.host_id)}
                onConnect={connect}
                onEditHost={onEditHost}
                onRemove={() => recentActions.remove.mutate(record.id)}
              />
            ))}
          </Section>
        )}

        <div className="flex flex-col py-1">
          <SidebarLink
            icon={<KeyRound className="h-3.5 w-3.5" />}
            label="Credentials"
            onClick={onOpenCredentials}
          />
          <SidebarLink
            icon={<FolderOpen className="h-3.5 w-3.5" />}
            label="Snippets"
            onClick={onOpenSnippets}
          />
        </div>
      </div>

      {menu && menuHost && (
        <HostContextMenu
          host={menuHost}
          x={menu.x}
          y={menu.y}
          actions={rowActions}
          onClose={() => setMenu(null)}
        />
      )}
    </div>
  )
}

/** What every row can do with its host. */
interface RowActions {
  connect: (host: Host) => void
  edit: (hostId: string) => void
  duplicate: (host: Host) => void
  toggleFavorite: (host: Host) => void
  startRename: (host: Host) => void
  remove: (host: Host) => void | Promise<void>
  openMenu: (host: Host, x: number, y: number) => void
}

function SidebarLink({
  icon,
  label,
  onClick,
}: {
  icon: ReactNode
  label: string
  onClick: () => void
}) {
  return (
    <button
      onClick={onClick}
      className="row-hover flex h-row items-center gap-2 px-3 text-left text-base text-text-secondary hover:text-text-primary"
    >
      {icon}
      {label}
    </button>
  )
}

function Section({
  label,
  count,
  icon,
  open,
  onToggle,
  action,
  children,
}: {
  label: string
  count?: number
  icon: ReactNode
  open: boolean
  onToggle: () => void
  action?: ReactNode
  children: ReactNode
}) {
  return (
    <div className="group/section">
      <div className="row-hover flex h-row w-full items-center gap-1.5 px-2">
        <button onClick={onToggle} aria-expanded={open} className="flex flex-1 items-center gap-1.5 text-left">
          {open ? (
            <ChevronDown className="h-3 w-3 text-text-muted" aria-hidden />
          ) : (
            <ChevronRight className="h-3 w-3 text-text-muted" aria-hidden />
          )}
          <span className="text-text-muted">{icon}</span>
          <span className="text-xs font-medium uppercase tracking-wider text-text-muted">
            {label}
          </span>
        </button>
        {count !== undefined && <span className="text-xs text-text-muted">{count}</span>}
        {action && (
          <span className="opacity-0 transition-opacity group-hover/section:opacity-100">
            {action}
          </span>
        )}
      </div>
      {open && children}
    </div>
  )
}

interface FolderBranchProps {
  node: ReturnType<typeof useHostTree>['roots'][number]
  depth: number
  expanded: Record<string, boolean>
  forceOpen: boolean
  onToggle: (id: string) => void
  actions: RowActions
  renamingId: string | null
  onRename: (host: Host, name: string) => void
  onCancelRename: () => void
}

function FolderBranch({
  node,
  depth,
  expanded,
  forceOpen,
  onToggle,
  actions,
  renamingId,
  onRename,
  onCancelRename,
}: FolderBranchProps) {
  const isOpen = forceOpen || expanded[node.folder.id] === true
  if (forceOpen && node.hosts.length === 0 && node.children.length === 0) return null

  return (
    <div>
      <button
        onClick={() => onToggle(node.folder.id)}
        aria-expanded={isOpen}
        className="row-hover flex h-row w-full items-center gap-1.5 pr-2 text-left"
        style={{ paddingLeft: 8 + depth * 12 }}
      >
        {isOpen ? (
          <ChevronDown className="h-3 w-3 shrink-0 text-text-muted" aria-hidden />
        ) : (
          <ChevronRight className="h-3 w-3 shrink-0 text-text-muted" aria-hidden />
        )}
        <FolderIcon
          className="h-3.5 w-3.5 shrink-0"
          style={{ color: node.folder.color || 'var(--text-muted)' }}
          aria-hidden
        />
        <span className="truncate text-base text-text-primary">{node.folder.name}</span>
        <span className="ml-auto shrink-0 text-xs text-text-muted">
          {node.hosts.length > 0 ? node.hosts.length : ''}
        </span>
      </button>

      {isOpen && (
        <>
          {node.children.map((child) => (
            <FolderBranch
              key={child.folder.id}
              node={child}
              depth={depth + 1}
              expanded={expanded}
              forceOpen={forceOpen}
              onToggle={onToggle}
              actions={actions}
              renamingId={renamingId}
              onRename={onRename}
              onCancelRename={onCancelRename}
            />
          ))}
          {node.hosts.map((host) => (
            <HostRow
              key={host.id}
              host={host}
              depth={depth + 1}
              actions={actions}
              renaming={renamingId === host.id}
              onRename={(name) => onRename(host, name)}
              onCancelRename={onCancelRename}
            />
          ))}
        </>
      )}
    </div>
  )
}

function HostRow({
  host,
  depth,
  actions,
  renaming,
  onRename,
  onCancelRename,
}: {
  host: Host
  depth: number
  actions: RowActions
  renaming: boolean
  onRename: (name: string) => void
  onCancelRename: () => void
}) {
  const selected = useUI((s) => s.selectedHostIds.includes(host.id))
  const toggleSelection = useUI((s) => s.toggleHostSelection)
  const desktop = isDesktopProtocol(host.protocol)

  return (
    <div
      className={clsx(
        'group row-hover flex h-row items-center gap-2 pr-1',
        selected && 'bg-accent-muted/20',
      )}
      style={{
        paddingLeft: 8 + depth * 12,
        // Colour renders as a left border rather than a filled chip: with three
        // hundred hosts on screen, filled colour becomes noise.
        boxShadow: host.color ? `inset 2px 0 0 ${host.color}` : undefined,
      }}
      onContextMenu={(event) => {
        event.preventDefault()
        actions.openMenu(host, event.clientX, event.clientY)
      }}
    >
      {renaming ? (
        <RenameField initial={host.name} onCommit={onRename} onCancel={onCancelRename} />
      ) : (
        <>
          <button
            onClick={(event) => {
              if (event.shiftKey) {
                toggleSelection(host.id)
                return
              }
              actions.connect(host)
            }}
            onDoubleClick={() => actions.startRename(host)}
            onKeyDown={(event) => {
              // F2 renames, matching every file manager and IDE.
              if (event.key === 'F2') {
                event.preventDefault()
                actions.startRename(host)
              }
            }}
            className="flex min-w-0 flex-1 items-center gap-2 text-left"
            title={`${host.username ? `${host.username}@` : ''}${host.hostname}:${host.port}`}
          >
            <StatusDot status={healthStatus(host)} />
            <ProtocolIcon protocol={host.protocol} className="text-text-muted" />
            <span className="truncate text-base text-text-primary">{host.name}</span>
            {host.is_favorite && (
              <Star
                className="h-3 w-3 shrink-0 fill-state-warning text-state-warning"
                aria-label="Favorite"
              />
            )}
          </button>

          <span className="hidden shrink-0 items-center gap-0.5 group-hover:flex">
            <IconButton
              label={desktop ? `Open a desktop on ${host.name}` : `Open a terminal on ${host.name}`}
              onClick={() => actions.connect(host)}
            >
              {desktop ? <Monitor className="h-3 w-3" /> : <TerminalIcon className="h-3 w-3" />}
            </IconButton>
            <IconButton label={`Edit ${host.name}`} onClick={() => actions.edit(host.id)}>
              <Pencil className="h-3 w-3" />
            </IconButton>
            <IconButton
              label={`More actions for ${host.name}`}
              onClick={(event) => {
                const rect = (event.currentTarget as HTMLElement).getBoundingClientRect()
                actions.openMenu(host, rect.right, rect.bottom)
              }}
            >
              <MoreVertical className="h-3 w-3" />
            </IconButton>
          </span>
        </>
      )}
    </div>
  )
}

/** Inline rename. Enter commits, Escape reverts, blur commits. */
function RenameField({
  initial,
  onCommit,
  onCancel,
}: {
  initial: string
  onCommit: (name: string) => void
  onCancel: () => void
}) {
  const [value, setValue] = useState(initial)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    inputRef.current?.select()
  }, [])

  return (
    <input
      ref={inputRef}
      value={value}
      autoFocus
      spellCheck={false}
      aria-label="Host name"
      className="field h-5 flex-1 text-base"
      onChange={(event) => setValue(event.target.value)}
      onKeyDown={(event) => {
        // Stop Escape and Enter reaching the tree's own handlers.
        event.stopPropagation()
        if (event.key === 'Enter') onCommit(value.trim())
        if (event.key === 'Escape') onCancel()
      }}
      onBlur={() => onCommit(value.trim())}
    />
  )
}

/**
 * A row in the Recent list.
 *
 * A record whose host has been deleted stays visible and offers only removal. The
 * alternative -- hiding it -- leaves an entry the user can see in history but never
 * act on, and a disabled row with no way to clear it is worse than either.
 */
function RecentRow({
  record,
  host,
  onConnect,
  onEditHost,
  onRemove,
}: {
  record: SessionRecord
  host: Host | undefined
  onConnect: (host: Host) => void
  onEditHost: (hostId: string) => void
  onRemove: () => void
}) {
  return (
    <div className="group row-hover flex h-row items-center gap-2 pr-1 pl-3">
      <button
        onClick={() => host && onConnect(host)}
        disabled={!host}
        className={clsx('flex min-w-0 flex-1 items-center gap-2 text-left', !host && 'opacity-50')}
        title={host ? `Connect to ${host.name}` : 'This host no longer exists'}
      >
        <StatusDot status={host ? healthStatus(host) : 'unknown'} />
        <span className="truncate text-base text-text-primary">
          {record.host_name || record.host_snapshot}
        </span>
        <span className="ml-auto shrink-0 text-xs text-text-muted">
          {formatRelative(record.started_at)}
        </span>
      </button>

      <span className="hidden shrink-0 items-center gap-0.5 group-hover:flex">
        {host && (
          <IconButton label={`Edit ${host.name}`} onClick={() => onEditHost(host.id)}>
            <Pencil className="h-3 w-3" />
          </IconButton>
        )}
        <IconButton label="Remove from Recent" onClick={onRemove}>
          <X className="h-3 w-3" />
        </IconButton>
      </span>
    </div>
  )
}

/**
 * The row context menu.
 *
 * Rendered at the pointer and clamped to the viewport, dismissed by Escape, an
 * outside click, or a scroll -- a menu still floating over a tree that has moved
 * underneath it would act on whatever row it now covers.
 */
function HostContextMenu({
  host,
  x,
  y,
  actions,
  onClose,
}: {
  host: Host
  x: number
  y: number
  actions: RowActions
  onClose: () => void
}) {
  const ref = useRef<HTMLDivElement>(null)
  const [position, setPosition] = useState({ left: x, top: y })

  useEffect(() => {
    const element = ref.current
    if (!element) return
    const { width, height } = element.getBoundingClientRect()
    setPosition({
      left: Math.min(x, window.innerWidth - width - 8),
      top: Math.min(y, window.innerHeight - height - 8),
    })
  }, [x, y])

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.stopPropagation()
        onClose()
      }
    }
    const onPointerDown = (event: PointerEvent) => {
      if (!ref.current?.contains(event.target as Node)) onClose()
    }

    window.addEventListener('keydown', onKeyDown, true)
    window.addEventListener('pointerdown', onPointerDown, true)
    window.addEventListener('scroll', onClose, true)
    return () => {
      window.removeEventListener('keydown', onKeyDown, true)
      window.removeEventListener('pointerdown', onPointerDown, true)
      window.removeEventListener('scroll', onClose, true)
    }
  }, [onClose])

  const run = (action: () => void) => () => {
    onClose()
    action()
  }

  const desktop = isDesktopProtocol(host.protocol)

  return (
    <div
      ref={ref}
      role="menu"
      aria-label={`Actions for ${host.name}`}
      className="fixed z-40 w-52 rounded border border-border-strong bg-surface-3 py-1"
      style={{ left: position.left, top: position.top, boxShadow: 'var(--shadow)' }}
    >
      <MenuItem
        icon={desktop ? <Monitor className="h-3.5 w-3.5" /> : <TerminalIcon className="h-3.5 w-3.5" />}
        label={desktop ? 'Open desktop' : 'Open terminal'}
        onClick={run(() => actions.connect(host))}
        autoFocus
      />
      <MenuItem
        icon={<Pencil className="h-3.5 w-3.5" />}
        label="Edit…"
        onClick={run(() => actions.edit(host.id))}
      />
      <MenuItem
        icon={<Copy className="h-3.5 w-3.5" />}
        label="Duplicate"
        onClick={run(() => actions.duplicate(host))}
      />
      <MenuItem
        icon={
          host.is_favorite ? <StarOff className="h-3.5 w-3.5" /> : <Star className="h-3.5 w-3.5" />
        }
        label={host.is_favorite ? 'Remove from favorites' : 'Add to favorites'}
        onClick={run(() => actions.toggleFavorite(host))}
      />
      <MenuItem
        icon={<Pencil className="h-3.5 w-3.5" />}
        label="Rename"
        hint="F2"
        onClick={run(() => actions.startRename(host))}
      />
      <div className="my-1 border-t border-border-subtle" />
      <MenuItem
        icon={<Trash2 className="h-3.5 w-3.5" />}
        label="Delete…"
        destructive
        onClick={run(() => void actions.remove(host))}
      />
    </div>
  )
}

function MenuItem({
  icon,
  label,
  hint,
  destructive,
  autoFocus,
  onClick,
}: {
  icon: ReactNode
  label: string
  hint?: string
  destructive?: boolean
  autoFocus?: boolean
  onClick: () => void
}) {
  return (
    <button
      role="menuitem"
      autoFocus={autoFocus}
      onClick={onClick}
      className={clsx(
        'flex w-full items-center gap-2 px-3 py-1 text-left text-base hover:bg-surface-2',
        destructive ? 'text-state-danger' : 'text-text-secondary hover:text-text-primary',
      )}
    >
      {icon}
      <span className="flex-1">{label}</span>
      {hint && <span className="text-xs text-text-muted">{hint}</span>}
    </button>
  )
}
