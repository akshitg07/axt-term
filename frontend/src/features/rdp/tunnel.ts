/**
 * The WebSocket tunnel for remote desktop sessions.
 *
 * guacamole-common-js ships its own WebSocketTunnel, and this exists instead of it
 * for one reason: authentication. AXT-Term's sockets are authorised by a
 * single-use ticket fetched over a CSRF-checked request, and reconnection follows
 * the same jittered backoff the terminal uses. Reusing the library's tunnel would
 * mean reusing the Guacamole web application's query-parameter token scheme.
 *
 * What it does reuse is Guacamole.Parser, so instruction decoding is the library's
 * tested implementation rather than a second one written here.
 *
 * Framing matches the Go side in internal/rdp/bridge.go: binary frames carry one
 * instruction behind a one-byte opcode, text frames carry JSON control messages.
 */

import { Parser, Status, Tunnel } from 'guacamole-common-js'

import { api } from '@/lib/api'
import type { TicketResponse } from '@/lib/types'

/** Binary opcode for an instruction frame, in both directions. */
export const OP_INSTRUCTION = 0x10

/** Control frames, mirroring internal/rdp/bridge.go. */
export interface DesktopControl {
  t: string
  width?: number
  height?: number
  state?: string
  host?: string
  repainted?: boolean
  protocol?: string
  code?: string
  message?: string
  reason?: string
}

/** Backoff schedule in milliseconds, matching lib/ws.ts. */
const BACKOFF_MS = [500, 1000, 2000, 4000, 8000, 8000]

function backoffDelay(attempt: number): number {
  const base = BACKOFF_MS[Math.min(attempt, BACKOFF_MS.length - 1)] ?? 8000
  // Jitter so many tabs reconnecting after a server restart do not arrive as one
  // synchronised herd.
  return base + Math.floor(Math.random() * 400)
}

function socketURL(path: string, params: Record<string, string>): string {
  const url = new URL(path, window.location.href)
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:'
  for (const [key, value] of Object.entries(params)) {
    if (value) url.searchParams.set(key, value)
  }
  return url.toString()
}

/**
 * Encodes one Guacamole instruction.
 *
 * The length prefix counts UTF-16 code units, which is what a JavaScript string's
 * `length` already is -- and what the Go reader expects. The two agreeing on this
 * is what keeps a clipboard paste containing an emoji from desynchronising the
 * stream.
 */
export function encodeInstruction(elements: Array<string | number>): string {
  let out = ''
  for (let i = 0; i < elements.length; i += 1) {
    const value = String(elements[i])
    out += `${i > 0 ? ',' : ''}${value.length}.${value}`
  }
  return `${out};`
}

export interface DesktopTunnelOptions {
  sessionId: string
  /** Viewport at connect time, so the server can size a rejoin correctly. */
  width: number
  height: number
  dpi: number
  /** Raised for control frames the client itself does not understand. */
  onControl?: (control: DesktopControl) => void
  /** Raised when the socket closes and whether another attempt is coming. */
  onClosed?: (willRetry: boolean, attempt: number) => void
}

/**
 * A Guacamole tunnel over AXT-Term's authenticated WebSocket.
 *
 * The state machine differs from the library's tunnels in one way worth knowing:
 * the guacd handshake has already happened server-side by the time this socket
 * exists, so there is no `ready` instruction to wait for. The tunnel reports OPEN
 * when the server's `status` control frame arrives, which is the moment the relay
 * is live.
 */
export class DesktopTunnel extends Tunnel {
  private ws: WebSocket | null = null
  private attempt = 0
  private closedByUs = false
  private retryTimer: number | null = null
  private readonly parser = new Parser()
  private readonly options: DesktopTunnelOptions

  constructor(options: DesktopTunnelOptions) {
    super()
    this.options = options
    this.uuid = options.sessionId
    this.state = Tunnel.CLOSED

    this.parser.oninstruction = (opcode, args) => {
      this.oninstruction?.(opcode, args)
    }
  }

  /** Current viewport, updated as the pane is resized. */
  private geometry(): Record<string, string> {
    return {
      width: String(Math.round(this.options.width)),
      height: String(Math.round(this.options.height)),
      dpi: String(Math.round(this.options.dpi)),
    }
  }

  /** Records a new viewport so a reconnect asks for the right size. */
  setGeometry(width: number, height: number): void {
    this.options.width = width
    this.options.height = height
  }

  override connect(): void {
    void this.open()
  }

  private async open(): Promise<void> {
    this.closedByUs = false
    this.clearRetry()
    this.setState(Tunnel.CONNECTING)

    let ticket: TicketResponse
    try {
      ticket = await api.post<TicketResponse>(`/api/v1/sessions/${this.options.sessionId}/ticket`)
    } catch (error) {
      this.scheduleRetry()
      this.onerror?.(
        new Status(
          0x0201,
          error instanceof Error ? error.message : 'Could not obtain a session ticket',
        ),
      )
      return
    }

    const ws = new WebSocket(
      socketURL('/ws/rdp', { ticket: ticket.ticket, ...this.geometry() }),
    )
    ws.binaryType = 'arraybuffer'
    this.ws = ws

    ws.onopen = () => {
      this.attempt = 0
    }

    ws.onmessage = (event: MessageEvent) => {
      if (typeof event.data === 'string') {
        this.handleControl(event.data)
        return
      }
      const frame = new Uint8Array(event.data as ArrayBuffer)
      if (frame.length < 2) return
      if (frame[0] !== OP_INSTRUCTION) return

      // Instructions are UTF-8 on the wire; the parser wants characters.
      this.parser.receive(new TextDecoder().decode(frame.subarray(1)))
    }

    ws.onerror = () => {
      // onclose always follows and carries the useful information.
    }

    ws.onclose = () => {
      this.ws = null
      const willRetry = !this.closedByUs
      this.setState(willRetry ? Tunnel.UNSTABLE : Tunnel.CLOSED)
      this.options.onClosed?.(willRetry, this.attempt)
      if (willRetry) this.scheduleRetry()
    }
  }

  private handleControl(raw: string): void {
    let control: DesktopControl
    try {
      control = JSON.parse(raw) as DesktopControl
    } catch {
      return
    }

    switch (control.t) {
      case 'status':
        // The relay is live. There is no `ready` instruction to wait for because
        // the handshake happened before this socket existed.
        this.setState(Tunnel.OPEN)
        break

      case 'exit':
        // A session that has ended is final; retrying would reconnect to nothing.
        this.closedByUs = true
        this.setState(Tunnel.CLOSED)
        break

      case 'error':
        this.onerror?.(new Status(0x0203, control.message ?? control.code ?? 'Desktop error'))
        break

      default:
        break
    }

    this.options.onControl?.(control)
  }

  private setState(state: number): void {
    if (this.state === state) return
    this.state = state
    this.onstatechange?.(state)
  }

  override sendMessage(...elements: Array<string | number>): void {
    if (this.ws?.readyState !== WebSocket.OPEN) return
    if (elements.length === 0) return

    const encoded = new TextEncoder().encode(encodeInstruction(elements))
    const frame = new Uint8Array(encoded.length + 1)
    frame[0] = OP_INSTRUCTION
    frame.set(encoded, 1)
    this.ws.send(frame)
  }

  /** Sends a JSON control frame, used for resize. */
  sendControl(control: DesktopControl): void {
    if (this.ws?.readyState !== WebSocket.OPEN) return
    this.ws.send(JSON.stringify(control))
  }

  override isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN
  }

  private scheduleRetry(): void {
    if (this.closedByUs || this.retryTimer !== null) return
    if (this.attempt >= BACKOFF_MS.length) {
      this.setState(Tunnel.CLOSED)
      return
    }
    const delay = backoffDelay(this.attempt)
    this.attempt += 1
    this.retryTimer = window.setTimeout(() => {
      this.retryTimer = null
      void this.open()
    }, delay)
  }

  private clearRetry(): void {
    if (this.retryTimer !== null) {
      window.clearTimeout(this.retryTimer)
      this.retryTimer = null
    }
  }

  override disconnect(): void {
    this.closedByUs = true
    this.clearRetry()
    // Tell the server before dropping the socket, so the desktop is released
    // rather than left for the idle sweeper.
    this.sendMessage('disconnect')
    this.ws?.close(1000, 'closed by client')
    this.ws = null
    this.setState(Tunnel.CLOSED)
  }
}
