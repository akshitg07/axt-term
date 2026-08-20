import { useMemo, useState, type ReactNode } from 'react'
import {
  ChevronDown,
  ChevronRight,
  Clock,
  Folder as FolderIcon,
  FolderOpen,
  KeyRound,
  Monitor,
  Network,
  Plus,
  Search,
  Server,
  Star,
  Terminal as TerminalIcon,
} from 'lucide-react'
import clsx from 'clsx'

import type { Host, Protocol } from '@/lib/types'
import { useFolders, useHostTree, useHosts, useOpenSession, useRecentSessions } from '@/lib/hooks'
import { useUI } from '@/lib/store'
import { EmptyState, IconButton, Spinner, StatusDot, type DotStatus } from '@/components/ui'
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
 */
export function Sidebar({ onNewHost, onOpenCredentials, onOpenSnippets }: SidebarProps) {
  const [filter, setFilter] = useState('')
  const [expanded, setExpanded] = useState<Record<string, boolean>>({})
  const [showFavorites, setShowFavorites] = useState(true)
  const [showRecent, setShowRecent] = useState(true)

  const hostsQuery = useHosts()
  const foldersQuery = useFolders()
  const recentQuery = useRecentSessions()
  const openSession = useOpenSession()

  const hosts = hostsQuery.data ?? []
  const folders = foldersQuery.data ?? []

  const filteredHosts = useMemo(
    () => fuzzyFilter(hosts, filter, (h) => `${h.name} ${h.hostname} ${h.tags.join(' ')}`),
    [hosts, filter],
  )
  const tree = useHostTree(filteredHosts, folders)

  const connect = (host: Host) => openSession.mutate({ host })
  const toggle = (id: string) => setExpanded((prev) => ({ ...prev, [id]: !prev[id] }))

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
              <HostRow key={`fav-${host.id}`} host={host} depth={1} onConnect={connect} />
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
            onConnect={connect}
          />
        ))}

        {tree.unfiled.length > 0 && (
          <div className="mt-1">
            {tree.unfiled.map((host) => (
              <HostRow key={host.id} host={host} depth={0} onConnect={connect} />
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
          >
            {(recentQuery.data ?? []).slice(0, 6).map((record) => {
              const host = hosts.find((h) => h.id === record.host_id)
              return (
                <button
                  key={record.id}
                  onClick={() => host && connect(host)}
                  disabled={!host}
                  className={clsx(
                    'row-hover flex h-row w-full items-center gap-2 px-3 text-left',
                    !host && 'opacity-50',
                  )}
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
              )
            })}
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
    </div>
  )
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
  children,
}: {
  label: string
  count?: number
  icon: ReactNode
  open: boolean
  onToggle: () => void
  children: ReactNode
}) {
  return (
    <div>
      <button
        onClick={onToggle}
        aria-expanded={open}
        className="row-hover flex h-row w-full items-center gap-1.5 px-2 text-left"
      >
        {open ? (
          <ChevronDown className="h-3 w-3 text-text-muted" aria-hidden />
        ) : (
          <ChevronRight className="h-3 w-3 text-text-muted" aria-hidden />
        )}
        <span className="text-text-muted">{icon}</span>
        <span className="text-xs font-medium uppercase tracking-wider text-text-muted">{label}</span>
        {count !== undefined && <span className="ml-auto text-xs text-text-muted">{count}</span>}
      </button>
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
  onConnect: (host: Host) => void
}

function FolderBranch({ node, depth, expanded, forceOpen, onToggle, onConnect }: FolderBranchProps) {
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
              onConnect={onConnect}
            />
          ))}
          {node.hosts.map((host) => (
            <HostRow key={host.id} host={host} depth={depth + 1} onConnect={onConnect} />
          ))}
        </>
      )}
    </div>
  )
}

function HostRow({
  host,
  depth,
  onConnect,
}: {
  host: Host
  depth: number
  onConnect: (host: Host) => void
}) {
  const selected = useUI((s) => s.selectedHostIds.includes(host.id))
  const toggleSelection = useUI((s) => s.toggleHostSelection)

  return (
    <div
      className={clsx(
        'group row-hover flex h-row items-center gap-2 pr-2',
        selected && 'bg-accent-muted/20',
      )}
      style={{
        paddingLeft: 8 + depth * 12,
        // Colour renders as a left border rather than a filled chip: with three
        // hundred hosts on screen, filled colour becomes noise.
        boxShadow: host.color ? `inset 2px 0 0 ${host.color}` : undefined,
      }}
    >
      <button
        onClick={(event) => {
          if (event.shiftKey) {
            toggleSelection(host.id)
            return
          }
          onConnect(host)
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
        <IconButton label={`Open a terminal on ${host.name}`} onClick={() => onConnect(host)}>
          <TerminalIcon className="h-3 w-3" />
        </IconButton>
      </span>
    </div>
  )
}
