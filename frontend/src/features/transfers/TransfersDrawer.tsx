import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowDownToLine, ArrowUpFromLine, RotateCcw, Trash2 } from 'lucide-react'
import clsx from 'clsx'

import { api } from '@/lib/api'
import type { Transfer } from '@/lib/types'
import { useTransfers } from '@/lib/hooks'
import { Badge, EmptyState, IconButton } from '@/components/ui'
import { formatBytes, formatETA, formatSpeed } from '@/lib/format'

/**
 * The transfers drawer.
 *
 * Deliberately not a modal and not inside a host's context tabs: it is about
 * everything running, and a transfer that vanishes when you switch hosts is a
 * transfer you stop trusting.
 */
export function TransfersDrawer() {
  const query = useTransfers()
  const queryClient = useQueryClient()

  const retry = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/transfers/${id}/retry`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['transfers'] }),
  })
  const remove = useMutation({
    mutationFn: (id: string) => api.del(`/api/v1/transfers/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['transfers'] }),
  })

  const transfers = query.data ?? []

  return (
    <div className="flex h-full min-h-0 flex-col bg-surface-1">
      <div className="flex h-7 shrink-0 items-center gap-2 border-b border-border-subtle px-2">
        <span className="text-xs font-medium uppercase tracking-wider text-text-muted">
          Transfers
        </span>
        {transfers.length > 0 && (
          <span className="text-xs text-text-muted">{transfers.length}</span>
        )}
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto">
        {transfers.length === 0 ? (
          <EmptyState
            title="No transfers"
            message="Uploads and downloads appear here with progress, speed, and a retry for anything that failed."
          />
        ) : (
          <ul className="divide-y divide-border-subtle">
            {transfers.map((transfer) => (
              <li key={transfer.id} className="flex items-center gap-3 px-3 py-2">
                {transfer.direction === 'upload' ? (
                  <ArrowUpFromLine className="h-3.5 w-3.5 shrink-0 text-text-muted" aria-label="Upload" />
                ) : (
                  <ArrowDownToLine className="h-3.5 w-3.5 shrink-0 text-text-muted" aria-label="Download" />
                )}

                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="truncate text-base text-text-primary">
                      {transfer.display_name}
                    </span>
                    <StatusBadge transfer={transfer} />
                    {transfer.host_name && (
                      <span className="shrink-0 text-xs text-text-muted">{transfer.host_name}</span>
                    )}
                  </div>

                  {transfer.status === 'active' && (
                    <Progress
                      transferred={transfer.transferred_bytes}
                      total={transfer.size_bytes}
                      speed={transfer.speed_bps}
                    />
                  )}
                  {transfer.error && (
                    <p className="mt-0.5 truncate text-sm text-state-danger">{transfer.error}</p>
                  )}
                </div>

                <div className="flex shrink-0 gap-0.5">
                  {(transfer.status === 'failed' ||
                    transfer.status === 'interrupted' ||
                    transfer.status === 'cancelled') && (
                    <IconButton label="Retry" onClick={() => retry.mutate(transfer.id)}>
                      <RotateCcw className="h-3.5 w-3.5" />
                    </IconButton>
                  )}
                  {transfer.status !== 'active' && (
                    <IconButton label="Remove" onClick={() => remove.mutate(transfer.id)}>
                      <Trash2 className="h-3.5 w-3.5" />
                    </IconButton>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}

function StatusBadge({ transfer }: { transfer: Transfer }) {
  switch (transfer.status) {
    case 'completed':
      return <Badge tone="success">done</Badge>
    case 'failed':
      return <Badge tone="danger">failed</Badge>
    case 'cancelled':
      return <Badge>cancelled</Badge>
    case 'interrupted':
      // Distinct from failed: the server restarted mid-transfer, so a retry is
      // very likely to succeed. Showing it honestly beats a stalled progress bar.
      return <Badge tone="warning">interrupted</Badge>
    case 'queued':
      return <Badge>queued</Badge>
    default:
      return <Badge tone="accent">active</Badge>
  }
}

function Progress({
  transferred,
  total,
  speed,
}: {
  transferred: number
  total: number | undefined
  speed: number
}) {
  const percent = total && total > 0 ? Math.min(100, Math.round((transferred / total) * 100)) : null

  return (
    <div className="mt-1">
      <div
        className="h-1 overflow-hidden rounded-full bg-surface-3"
        role="progressbar"
        aria-valuenow={percent ?? undefined}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        <div
          className={clsx('h-full rounded-full bg-accent transition-[width]', percent === null && 'animate-pulse-slow')}
          style={{ width: percent === null ? '35%' : `${percent}%` }}
        />
      </div>
      <p className="mt-0.5 flex gap-2 text-xs text-text-muted">
        <span>
          {formatBytes(transferred)}
          {total ? ` / ${formatBytes(total)}` : ''}
          {percent !== null ? ` · ${percent}%` : ''}
        </span>
        <span>{formatSpeed(speed)}</span>
        <span>ETA {formatETA(transferred, total, speed)}</span>
      </p>
    </div>
  )
}
