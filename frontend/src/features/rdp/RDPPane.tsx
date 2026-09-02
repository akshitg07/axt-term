import { useCallback, useEffect, useRef, useState } from 'react'
import { Client, Keyboard, Mouse, StringReader, StringWriter, Tunnel } from 'guacamole-common-js'
import {
  ClipboardPaste,
  Command,
  Maximize2,
  Monitor,
  RefreshCw,
  Scan,
} from 'lucide-react'
import clsx from 'clsx'

import { useUI, type Tab } from '@/lib/store'
import type { Host } from '@/lib/types'
import { IconButton, StatusDot } from '@/components/ui'
import { DesktopTunnel, type DesktopControl } from './tunnel'

/** X11 keysyms for the keys the toolbar sends. */
const KEYSYM = {
  controlLeft: 0xffe3,
  altLeft: 0xffe9,
  delete: 0xffff,
  shiftLeft: 0xffe1,
  escape: 0xff1b,
  superLeft: 0xffeb,
} as const

/** How long to wait after the last resize event before telling the server. */
const RESIZE_DEBOUNCE_MS = 250

type ConnectionState = 'connecting' | 'open' | 'retrying' | 'closed'

interface RDPPaneProps {
  tab: Tab
  host: Host | undefined
}

/**
 * A remote desktop, rendered by guacamole-common-js.
 *
 * The pane owns a Guacamole client and a tunnel; the *session* belongs to the
 * backend, so switching tabs or reloading does not end the desktop. What differs
 * from the terminal is how coming back works: an instruction stream is a sequence
 * of drawing operations rather than a byte stream, so there is nothing to replay.
 * The server joins the existing guacd connection instead, which makes guacd repaint
 * the whole display -- and the `repainted` flag on the status frame is how this pane
 * knows that is what happened.
 */
export function RDPPane({ tab, host }: RDPPaneProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const wrapperRef = useRef<HTMLDivElement>(null)
  const clientRef = useRef<Client | null>(null)
  const tunnelRef = useRef<DesktopTunnel | null>(null)
  const keyboardRef = useRef<Keyboard | null>(null)
  const resizeTimer = useRef<number | null>(null)

  const pushToast = useUI((s) => s.pushToast)
  const updateTab = useUI((s) => s.updateTab)

  const [connection, setConnection] = useState<ConnectionState>('connecting')
  const [remoteSize, setRemoteSize] = useState<{ width: number; height: number } | null>(null)
  // Scaling to fit is the default: a 1920x1080 desktop inside a smaller pane is
  // otherwise cropped, and cropping a desktop hides the taskbar.
  const [fitToWindow, setFitToWindow] = useState(true)

  const clipboardEnabled = host?.rdp_options.enable_clipboard ?? false
  const sessionId = tab.sessionId

  /** Rescales the display to the pane, or restores 1:1. */
  const applyScale = useCallback(() => {
    const client = clientRef.current
    const wrapper = wrapperRef.current
    if (!client || !wrapper) return

    const display = client.getDisplay()
    const width = display.getWidth()
    const height = display.getHeight()
    if (width === 0 || height === 0) return

    if (!fitToWindow) {
      display.scale(1)
      return
    }
    const scale = Math.min(wrapper.clientWidth / width, wrapper.clientHeight / height, 1)
    display.scale(scale > 0 ? scale : 1)
  }, [fitToWindow])

  // --- create the client once per session -------------------------------
  useEffect(() => {
    if (!sessionId || !containerRef.current || !wrapperRef.current) return

    const wrapper = wrapperRef.current
    const tunnel = new DesktopTunnel({
      sessionId,
      width: Math.max(wrapper.clientWidth, 640),
      height: Math.max(wrapper.clientHeight, 480),
      dpi: Math.round(96 * (window.devicePixelRatio || 1)),
      onControl: (control: DesktopControl) => {
        if (control.t === 'status') {
          if (control.width && control.height) {
            setRemoteSize({ width: control.width, height: control.height })
          }
          return
        }
        if (control.t === 'error' && control.code === 'viewer_replaced') {
          // Not a failure: somebody opened the same desktop elsewhere. Saying so
          // beats a pane that silently stops updating.
          pushToast({
            level: 'warning',
            title: 'This desktop was opened in another view',
            message: 'Only one view at a time receives the display.',
          })
          return
        }
        if (control.t === 'exit') {
          updateTab(tab.id, { state: 'disconnected', exitReason: control.reason })
        }
      },
      onClosed: (willRetry) => setConnection(willRetry ? 'retrying' : 'closed'),
    })

    const client = new Client(tunnel)
    clientRef.current = client
    tunnelRef.current = tunnel

    const display = client.getDisplay()
    containerRef.current.appendChild(display.getElement())

    display.onresize = (width, height) => {
      setRemoteSize({ width, height })
      applyScale()
    }

    client.onstatechange = () => {
      // Tunnel state is the honest signal here: the client's own states describe
      // its handshake, which happened server-side before this socket existed.
    }

    tunnel.onstatechange = (state) => {
      switch (state) {
        case Tunnel.OPEN:
          setConnection('open')
          break
        case Tunnel.CONNECTING:
          setConnection('connecting')
          break
        case Tunnel.UNSTABLE:
          setConnection('retrying')
          break
        default:
          setConnection('closed')
      }
    }

    tunnel.onerror = (status) => {
      pushToast({
        level: 'error',
        title: 'Remote desktop error',
        message: status.message ?? `Guacamole status ${status.code}`,
      })
    }

    client.onerror = (status) => {
      pushToast({
        level: 'error',
        title: 'The desktop reported an error',
        message: status.message ?? `Guacamole status ${status.code}`,
      })
    }

    // The remote window title is genuinely useful on a Windows box with several
    // apps open, so it replaces the tab's host name once known.
    client.onname = (name) => {
      if (name) updateTab(tab.id, { hostName: name })
    }

    if (clipboardEnabled) {
      client.onclipboard = (stream, mimetype) => {
        if (!mimetype.startsWith('text/')) {
          stream.sendAck('only text is accepted', 0x0100)
          return
        }
        const reader = new StringReader(stream)
        let text = ''
        reader.ontext = (chunk) => {
          text += chunk
        }
        reader.onend = () => {
          // Writing to the local clipboard can be refused when the document is not
          // focused, which is normal rather than an error worth a toast.
          void navigator.clipboard.writeText(text).catch(() => undefined)
        }
      }
    }

    // --- input ---------------------------------------------------------
    const mouse = new Mouse(display.getElement())
    const sendMouse = (state: Mouse.State) => {
      const scale = display.getScale() || 1
      client.sendMouseState(
        new Mouse.State(
          state.x / scale,
          state.y / scale,
          state.left,
          state.middle,
          state.right,
          state.up,
          state.down,
        ),
      )
    }
    mouse.onmousedown = sendMouse
    mouse.onmouseup = sendMouse
    mouse.onmousemove = sendMouse

    // Attached to the wrapper rather than the document, so the desktop only
    // swallows keystrokes while it has focus and application shortcuts keep
    // working everywhere else.
    const keyboard = new Keyboard(wrapper)
    keyboardRef.current = keyboard
    keyboard.onkeydown = (keysym) => {
      client.sendKeyEvent(1, keysym)
      // Returning false asks the library to suppress the browser's default, which
      // is what stops Ctrl+W closing the tab mid-session.
      return false
    }
    keyboard.onkeyup = (keysym) => client.sendKeyEvent(0, keysym)

    client.connect()

    return () => {
      keyboard.reset()
      keyboardRef.current = null
      mouse.onmousedown = null
      mouse.onmouseup = null
      mouse.onmousemove = null
      client.onclipboard = null
      client.onname = null
      display.onresize = null

      // Disconnect the tunnel, not the session: the desktop stays alive on the
      // server so returning to this tab shows the same screen.
      tunnel.disconnect()
      clientRef.current = null
      tunnelRef.current = null

      const element = display.getElement()
      element.parentNode?.removeChild(element)
    }
    // One client per session. Clipboard and scaling changes are handled by the
    // effects below rather than by tearing the desktop down.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId])

  // --- follow the pane size --------------------------------------------
  useEffect(() => {
    const wrapper = wrapperRef.current
    if (!wrapper) return

    const observer = new ResizeObserver(() => {
      applyScale()

      // Debounced: dragging a split divider or a browser window edge produces a
      // continuous stream of sizes, and each one server-side is an RDP display
      // reconfiguration.
      if (resizeTimer.current !== null) window.clearTimeout(resizeTimer.current)
      resizeTimer.current = window.setTimeout(() => {
        resizeTimer.current = null
        const tunnel = tunnelRef.current
        if (!tunnel || !fitToWindow) return

        const width = Math.round(wrapper.clientWidth)
        const height = Math.round(wrapper.clientHeight)
        if (width < 640 || height < 480) return

        tunnel.setGeometry(width, height)
        tunnel.sendControl({ t: 'resize', width, height })
      }, RESIZE_DEBOUNCE_MS)
    })
    observer.observe(wrapper)

    return () => {
      observer.disconnect()
      if (resizeTimer.current !== null) {
        window.clearTimeout(resizeTimer.current)
        resizeTimer.current = null
      }
    }
  }, [applyScale, fitToWindow])

  useEffect(() => {
    applyScale()
  }, [applyScale])

  /** Sends a chord as press-all then release-all, which is how RDP expects it. */
  const sendChord = useCallback((keysyms: number[]) => {
    const client = clientRef.current
    if (!client) return
    for (const keysym of keysyms) client.sendKeyEvent(1, keysym)
    for (const keysym of [...keysyms].reverse()) client.sendKeyEvent(0, keysym)
    wrapperRef.current?.focus()
  }, [])

  const pasteToRemote = useCallback(async () => {
    const client = clientRef.current
    if (!client) return
    if (!clipboardEnabled) {
      pushToast({
        level: 'warning',
        title: 'Clipboard is disabled for this host',
        message: 'Enable it in the host settings; it is off by default.',
      })
      return
    }
    try {
      const text = await navigator.clipboard.readText()
      if (!text) return
      const stream = client.createClipboardStream('text/plain')
      const writer = new StringWriter(stream)
      writer.sendText(text)
      writer.sendEnd()
      pushToast({ level: 'success', title: 'Clipboard sent to the desktop' })
    } catch {
      pushToast({
        level: 'warning',
        title: 'Could not read the clipboard',
        message: 'Browsers restrict programmatic reads; click the desktop and press Ctrl+V.',
      })
    }
  }, [clipboardEnabled, pushToast])

  const reconnect = useCallback(() => {
    const tunnel = tunnelRef.current
    if (!tunnel) return
    setConnection('connecting')
    tunnel.connect()
  }, [])

  const frozen = tab.state === 'disconnected' || tab.state === 'failed' || tab.state === 'closed'

  return (
    <div className="flex h-full min-h-0 flex-col bg-surface-0">
      <div className="flex h-7 shrink-0 items-center gap-1 border-b border-border-subtle bg-surface-1 px-2">
        <DesktopBadge state={connection} frozen={frozen} />
        <span className="ml-1 truncate text-sm text-text-secondary">{tab.hostName}</span>
        <span className="shrink-0 text-xs uppercase text-text-muted">{tab.protocol}</span>
        {remoteSize && (
          <span className="shrink-0 text-xs text-text-muted">
            {remoteSize.width}×{remoteSize.height}
          </span>
        )}
        {!clipboardEnabled && (
          <span className="shrink-0 text-xs text-text-muted" title="Enable it in host settings">
            clipboard off
          </span>
        )}

        <div className="ml-auto flex items-center gap-0.5">
          <IconButton label="Send Ctrl+Alt+Delete" onClick={() => sendChord([KEYSYM.controlLeft, KEYSYM.altLeft, KEYSYM.delete])}>
            <Command className="h-3.5 w-3.5" />
          </IconButton>
          <IconButton label="Send the Windows key" onClick={() => sendChord([KEYSYM.superLeft])}>
            <Monitor className="h-3.5 w-3.5" />
          </IconButton>
          <IconButton label="Paste into the desktop" onClick={pasteToRemote}>
            <ClipboardPaste className="h-3.5 w-3.5" />
          </IconButton>
          <IconButton
            label={fitToWindow ? 'Show at full size' : 'Scale to fit the pane'}
            active={fitToWindow}
            onClick={() => setFitToWindow((fit) => !fit)}
          >
            <Scan className="h-3.5 w-3.5" />
          </IconButton>
          <IconButton label="Reconnect this view" onClick={reconnect}>
            <RefreshCw className="h-3.5 w-3.5" />
          </IconButton>
          <IconButton label="Fullscreen" onClick={() => wrapperRef.current?.requestFullscreen?.()}>
            <Maximize2 className="h-3.5 w-3.5" />
          </IconButton>
        </div>
      </div>

      <div
        ref={wrapperRef}
        tabIndex={0}
        aria-label={`Remote desktop on ${tab.hostName}`}
        className={clsx(
          'relative min-h-0 flex-1 outline-none',
          fitToWindow ? 'overflow-hidden' : 'overflow-auto',
        )}
      >
        {/* The Guacamole display element is appended here and positions itself. */}
        <div ref={containerRef} className="flex h-full w-full items-center justify-center" />

        {frozen && (
          <div className="absolute inset-0 flex items-end justify-center bg-surface-0/40 backdrop-blur-[1px]">
            <div className="mb-8 rounded border border-border-strong bg-surface-3 px-3 py-2 text-center">
              <p className="text-base text-text-primary">Desktop ended</p>
              <p className="mt-0.5 max-w-xs text-sm text-text-secondary">
                {tab.exitReason ?? 'The connection closed.'}
              </p>
              <p className="mt-1 text-xs text-text-muted">
                Input is disabled. Reconnect from the tab menu to start a new desktop.
              </p>
            </div>
          </div>
        )}

        {connection === 'retrying' && !frozen && (
          <div className="absolute right-3 top-3 flex items-center gap-1.5 rounded border border-border-strong bg-surface-3 px-2 py-1 text-sm">
            <StatusDot status="connecting" />
            <span className="text-text-secondary">Reconnecting…</span>
          </div>
        )}

        {connection === 'connecting' && !frozen && (
          <div className="absolute inset-0 flex items-center justify-center">
            <span className="text-sm text-text-muted">Waiting for the desktop…</span>
          </div>
        )}
      </div>
    </div>
  )
}

function DesktopBadge({ state, frozen }: { state: ConnectionState; frozen: boolean }) {
  if (frozen) {
    return (
      <span className="flex items-center gap-1.5">
        <StatusDot status="error" />
        <span className="text-sm text-text-muted">Disconnected</span>
      </span>
    )
  }
  const map = {
    connecting: { dot: 'connecting', label: 'Connecting' },
    open: { dot: 'online', label: 'Connected' },
    retrying: { dot: 'connecting', label: 'Reconnecting' },
    closed: { dot: 'offline', label: 'Closed' },
  } as const

  const entry = map[state]
  return (
    <span className="flex items-center gap-1.5">
      <StatusDot status={entry.dot} />
      <span className={clsx('text-sm', state === 'open' ? 'text-text-secondary' : 'text-accent')}>
        {entry.label}
      </span>
    </span>
  )
}
