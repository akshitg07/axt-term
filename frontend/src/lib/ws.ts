/**
 * WebSocket clients.
 *
 * Two sockets, deliberately. Terminal I/O gets its own so a burst of transfer
 * progress events cannot delay keystroke echo, and the notification stream gets
 * its own so it can reconnect independently.
 *
 * Framing matches the Go side in internal/terminal/protocol.go: binary frames
 * carry data with a one-byte opcode, text frames carry JSON control messages. A
 * keystroke does not pay for JSON encoding, and terminal output does not pay for
 * base64.
 */

import { api } from './api'
import type { TicketResponse } from './types'

export const OP_OUTPUT = 0x00
export const OP_INPUT = 0x01
export const OP_REPLAY = 0x02

export interface Control {
  t: string
  cols?: number
  rows?: number
  state?: string
  seq?: number
  reset?: boolean
  host?: string
  recording?: boolean
  code?: string
  message?: string
  exit_code?: number
  reason?: string
}

export type TerminalEvent =
  | { kind: 'output'; data: Uint8Array }
  | { kind: 'replay'; data: Uint8Array; reset: boolean; seq: number }
  | { kind: 'status'; control: Control }
  | { kind: 'error'; control: Control }
  | { kind: 'exit'; control: Control }
  | { kind: 'open' }
  | { kind: 'closed'; willRetry: boolean; attempt: number }

function socketURL(path: string, params: Record<string, string>): string {
  const url = new URL(path, window.location.href)
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:'
  for (const [key, value] of Object.entries(params)) {
    if (value) url.searchParams.set(key, value)
  }
  return url.toString()
}

/** Backoff schedule for reconnection, in milliseconds. */
const BACKOFF_MS = [500, 1000, 2000, 4000, 8000, 8000]

function backoffDelay(attempt: number): number {
  const base = BACKOFF_MS[Math.min(attempt, BACKOFF_MS.length - 1)] ?? 8000
  // Jitter so twenty tabs reconnecting after a server restart do not arrive as
  // one synchronised thundering herd.
  return base + Math.floor(Math.random() * 400)
}

/**
 * TerminalSocket attaches to a backend session and reconnects on its own.
 *
 * It tracks the absolute byte offset it has seen so a reattach asks only for the
 * delta. It never re-sends input: a keystroke in flight when the socket died is
 * dropped, because replaying it would execute something on the user's behalf
 * after a reconnect.
 */
export class TerminalSocket {
  private ws: WebSocket | null = null
  private attempt = 0
  private closedByUs = false
  private seq = 0
  private retryTimer: number | null = null
  private readonly listeners = new Set<(event: TerminalEvent) => void>()

  constructor(private readonly sessionId: string) {}

  on(listener: (event: TerminalEvent) => void): () => void {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  private emit(event: TerminalEvent): void {
    for (const listener of this.listeners) listener(event)
  }

  /** Current absolute offset, so a caller can persist it across a reload. */
  get offset(): number {
    return this.seq
  }

  async connect(): Promise<void> {
    this.closedByUs = false
    this.clearRetry()

    let ticket: TicketResponse
    try {
      ticket = await api.post<TicketResponse>(`/api/v1/sessions/${this.sessionId}/ticket`)
    } catch (error) {
      this.scheduleRetry()
      this.emit({
        kind: 'error',
        control: {
          t: 'error',
          code: 'ticket_failed',
          message: error instanceof Error ? error.message : 'Could not obtain a session ticket',
        },
      })
      return
    }

    const url = socketURL('/ws/terminal', {
      ticket: ticket.ticket,
      seq: this.seq > 0 ? String(this.seq) : '',
    })

    const ws = new WebSocket(url)
    ws.binaryType = 'arraybuffer'
    this.ws = ws

    ws.onopen = () => {
      this.attempt = 0
      this.emit({ kind: 'open' })
    }

    ws.onmessage = (event: MessageEvent) => {
      if (typeof event.data === 'string') {
        this.handleControl(event.data)
        return
      }
      const frame = new Uint8Array(event.data as ArrayBuffer)
      if (frame.length === 0) return
      const payload = frame.subarray(1)
      this.seq += payload.length

      if (frame[0] === OP_REPLAY) {
        this.emit({ kind: 'replay', data: payload, reset: false, seq: this.seq })
      } else if (frame[0] === OP_OUTPUT) {
        this.emit({ kind: 'output', data: payload })
      }
    }

    ws.onerror = () => {
      // onclose always follows, and carries the useful information.
    }

    ws.onclose = () => {
      this.ws = null
      const willRetry = !this.closedByUs
      this.emit({ kind: 'closed', willRetry, attempt: this.attempt })
      if (willRetry) this.scheduleRetry()
    }
  }

  private handleControl(raw: string): void {
    let control: Control
    try {
      control = JSON.parse(raw) as Control
    } catch {
      return
    }

    switch (control.t) {
      case 'status':
        if (typeof control.seq === 'number') this.seq = control.seq
        this.emit({ kind: 'status', control })
        break
      case 'exit':
        // A clean exit is final; do not fight it with reconnection attempts.
        this.closedByUs = true
        this.emit({ kind: 'exit', control })
        break
      case 'error':
        this.emit({ kind: 'error', control })
        break
      case 'ack':
        break
      default:
        break
    }
  }

  private scheduleRetry(): void {
    if (this.closedByUs || this.retryTimer !== null) return
    if (this.attempt >= BACKOFF_MS.length) return
    const delay = backoffDelay(this.attempt)
    this.attempt += 1
    this.retryTimer = window.setTimeout(() => {
      this.retryTimer = null
      void this.connect()
    }, delay)
  }

  private clearRetry(): void {
    if (this.retryTimer !== null) {
      window.clearTimeout(this.retryTimer)
      this.retryTimer = null
    }
  }

  /** Sends keystrokes. Silently dropped when not connected -- see the class note. */
  send(data: string): void {
    if (this.ws?.readyState !== WebSocket.OPEN) return
    const encoded = new TextEncoder().encode(data)
    const frame = new Uint8Array(encoded.length + 1)
    frame[0] = OP_INPUT
    frame.set(encoded, 1)
    this.ws.send(frame)
  }

  resize(cols: number, rows: number): void {
    this.sendControl({ t: 'resize', cols, rows })
  }

  private sendControl(control: Control): void {
    if (this.ws?.readyState !== WebSocket.OPEN) return
    this.ws.send(JSON.stringify(control))
  }

  get connected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN
  }

  close(): void {
    this.closedByUs = true
    this.clearRetry()
    this.ws?.close(1000, 'closed by client')
    this.ws = null
    this.listeners.clear()
  }
}

/** One event from the notification stream. */
export interface ServerEvent {
  t: string
  at?: string
  [key: string]: unknown
}

/**
 * EventSocket carries transfer progress, health changes, job results, and
 * notifications for the signed-in user.
 */
export class EventSocket {
  private ws: WebSocket | null = null
  private attempt = 0
  private closedByUs = false
  private retryTimer: number | null = null
  private readonly listeners = new Set<(event: ServerEvent) => void>()

  on(listener: (event: ServerEvent) => void): () => void {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  async connect(): Promise<void> {
    this.closedByUs = false
    if (this.retryTimer !== null) {
      window.clearTimeout(this.retryTimer)
      this.retryTimer = null
    }

    let ticket: TicketResponse
    try {
      ticket = await api.post<TicketResponse>('/api/v1/events/ticket')
    } catch {
      this.scheduleRetry()
      return
    }

    const ws = new WebSocket(socketURL('/ws/events', { ticket: ticket.ticket }))
    this.ws = ws

    ws.onopen = () => {
      this.attempt = 0
    }
    ws.onmessage = (event: MessageEvent) => {
      if (typeof event.data !== 'string') return
      try {
        const parsed = JSON.parse(event.data) as ServerEvent
        for (const listener of this.listeners) listener(parsed)
      } catch {
        // A malformed event is not worth disturbing the user over.
      }
    }
    ws.onclose = () => {
      this.ws = null
      if (!this.closedByUs) this.scheduleRetry()
    }
  }

  private scheduleRetry(): void {
    if (this.closedByUs || this.retryTimer !== null) return
    const delay = backoffDelay(this.attempt)
    this.attempt += 1
    this.retryTimer = window.setTimeout(() => {
      this.retryTimer = null
      void this.connect()
    }, delay)
  }

  close(): void {
    this.closedByUs = true
    if (this.retryTimer !== null) window.clearTimeout(this.retryTimer)
    this.ws?.close(1000, 'closed by client')
    this.ws = null
    this.listeners.clear()
  }
}
