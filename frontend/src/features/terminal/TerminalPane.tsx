import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { SearchAddon } from '@xterm/addon-search'
import { WebLinksAddon } from '@xterm/addon-web-links'
import { WebglAddon } from '@xterm/addon-webgl'
import { Unicode11Addon } from '@xterm/addon-unicode11'
import {
  Circle,
  ClipboardCopy,
  ClipboardPaste,
  Eraser,
  Maximize2,
  Search,
  Video,
  VideoOff,
} from 'lucide-react'
import clsx from 'clsx'

import '@xterm/xterm/css/xterm.css'
import { TerminalSocket, type TerminalEvent } from '@/lib/ws'
import { useUI, type Tab } from '@/lib/store'
import { terminalThemeById } from './themes'
import { Badge, IconButton, Input, StatusDot } from '@/components/ui'
import { api } from '@/lib/api'

interface TerminalPaneProps {
  tab: Tab
}

/**
 * A real interactive terminal.
 *
 * The pane owns an xterm.js instance and a TerminalSocket; the *session* belongs
 * to the backend. That is why unmounting this component -- switching tabs, closing
 * the browser -- does not kill a running command, and why remounting replays only
 * what was missed.
 */
export function TerminalPane({ tab }: TerminalPaneProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const termRef = useRef<Terminal | null>(null)
  const fitRef = useRef<FitAddon | null>(null)
  const searchRef = useRef<SearchAddon | null>(null)
  const socketRef = useRef<TerminalSocket | null>(null)

  const terminalTheme = useUI((s) => s.terminalTheme)
  const fontSize = useUI((s) => s.terminalFontSize)
  const updateTab = useUI((s) => s.updateTab)
  const pushToast = useUI((s) => s.pushToast)

  const [connection, setConnection] = useState<'connecting' | 'open' | 'retrying' | 'closed'>(
    'connecting',
  )
  const [searchOpen, setSearchOpen] = useState(false)
  const [searchTerm, setSearchTerm] = useState('')
  const [recording, setRecording] = useState(false)

  const theme = useMemo(() => terminalThemeById(terminalTheme), [terminalTheme])

  // --- create the terminal once -----------------------------------------
  useEffect(() => {
    if (!containerRef.current) return

    const term = new Terminal({
      fontFamily: '"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace',
      fontSize,
      lineHeight: 1.2,
      theme,
      cursorBlink: true,
      cursorStyle: 'block',
      // 10k lines of scrollback is roughly what an engineer scrolls back through
      // in practice, and costs a few MB.
      scrollback: 10_000,
      allowProposedApi: true,
      macOptionIsMeta: true,
      // The bell is off by default: a terminal that beeps in a background tab is
      // startling and rarely informative.
      drawBoldTextInBrightColors: true,
      convertEol: false,
    })

    const fit = new FitAddon()
    const search = new SearchAddon()
    term.loadAddon(fit)
    term.loadAddon(search)
    term.loadAddon(new WebLinksAddon())

    const unicode = new Unicode11Addon()
    term.loadAddon(unicode)
    term.unicode.activeVersion = '11'

    term.open(containerRef.current)

    // WebGL keeps 60fps under heavy output, but it is not available everywhere and
    // can be lost when a GPU context is dropped. Falling back to the DOM renderer
    // is slower but correct, and far better than a blank pane.
    try {
      const webgl = new WebglAddon()
      webgl.onContextLoss(() => webgl.dispose())
      term.loadAddon(webgl)
    } catch {
      // DOM renderer remains active.
    }

    termRef.current = term
    fitRef.current = fit
    searchRef.current = search
    fit.fit()

    return () => {
      term.dispose()
      termRef.current = null
      fitRef.current = null
      searchRef.current = null
    }
    // Created once per tab; theme and font size are applied by the effects below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // --- apply appearance changes without recreating the terminal ---------
  useEffect(() => {
    const term = termRef.current
    if (!term) return
    term.options.theme = theme
    term.options.fontSize = fontSize
    fitRef.current?.fit()
  }, [theme, fontSize])

  // --- connect the socket ----------------------------------------------
  useEffect(() => {
    const term = termRef.current
    if (!term || !tab.sessionId) return

    const socket = new TerminalSocket(tab.sessionId)
    socketRef.current = socket

    const off = socket.on((event: TerminalEvent) => {
      switch (event.kind) {
        case 'open':
          setConnection('open')
          // Report the real geometry as soon as the socket is up, so the remote
          // shell wraps at the width actually on screen.
          if (fitRef.current) {
            const dims = fitRef.current.proposeDimensions()
            if (dims) socket.resize(dims.cols, dims.rows)
          }
          break

        case 'replay':
          // A gap means output was lost. Appending after a hole produces corruption
          // that looks like a terminal bug, so the display is reset instead.
          if (event.reset) term.reset()
          term.write(event.data)
          updateTab(tab.id, { seq: event.seq })
          break

        case 'output':
          term.write(event.data)
          break

        case 'status':
          if (event.control.state) {
            updateTab(tab.id, { state: event.control.state as Tab['state'] })
          }
          setRecording(Boolean(event.control.recording))
          break

        case 'error':
          term.write(`\r\n\x1b[33m[axt] ${event.control.message ?? 'error'}\x1b[0m\r\n`)
          break

        case 'exit':
          setConnection('closed')
          updateTab(tab.id, { state: 'disconnected', exitReason: event.control.reason })
          term.write(
            `\r\n\x1b[90m[axt] ${event.control.reason ?? 'session ended'}\x1b[0m\r\n`,
          )
          break

        case 'closed':
          setConnection(event.willRetry ? 'retrying' : 'closed')
          if (!event.willRetry) {
            updateTab(tab.id, { state: 'disconnected' })
          }
          break
      }
    })

    const disposeInput = term.onData((data) => socket.send(data))
    void socket.connect()

    return () => {
      off()
      disposeInput.dispose()
      socket.close()
      socketRef.current = null
    }
  }, [tab.sessionId, tab.id, updateTab])

  // --- resize ----------------------------------------------------------
  useEffect(() => {
    if (!containerRef.current) return

    let frame = 0
    const observer = new ResizeObserver(() => {
      // Debounced through a frame: dragging a divider fires per frame, and each
      // one would otherwise be a window-change request on the wire.
      cancelAnimationFrame(frame)
      frame = requestAnimationFrame(() => {
        const fit = fitRef.current
        if (!fit) return
        fit.fit()
        const dims = fit.proposeDimensions()
        if (dims && socketRef.current?.connected) {
          socketRef.current.resize(dims.cols, dims.rows)
        }
      })
    })
    observer.observe(containerRef.current)
    return () => {
      cancelAnimationFrame(frame)
      observer.disconnect()
    }
  }, [])

  // --- snippet insertion ------------------------------------------------
  // The snippets panel dispatches a window event rather than reaching into this
  // component, which keeps the socket owned in exactly one place. Insertion goes
  // through the same path as typing, so the shell echoes it identically.
  useEffect(() => {
    const onInsert = (event: Event) => {
      const detail = (event as CustomEvent<{ sessionId: string; text: string }>).detail
      if (!detail || detail.sessionId !== tab.sessionId) return
      socketRef.current?.send(detail.text)
      termRef.current?.focus()
    }
    window.addEventListener('axt:insert-into-terminal', onInsert)
    return () => window.removeEventListener('axt:insert-into-terminal', onInsert)
  }, [tab.sessionId])

  // --- toolbar actions -------------------------------------------------
  const copySelection = useCallback(async () => {
    const selection = termRef.current?.getSelection()
    if (!selection) return
    try {
      await navigator.clipboard.writeText(selection)
    } catch {
      pushToast({
        level: 'warning',
        title: 'Could not access the clipboard',
        message: 'Use Ctrl+Shift+C, or grant clipboard permission to this site.',
      })
    }
  }, [pushToast])

  const paste = useCallback(async () => {
    try {
      const text = await navigator.clipboard.readText()
      if (text) socketRef.current?.send(text)
    } catch {
      pushToast({
        level: 'warning',
        title: 'Could not read the clipboard',
        message: 'Use Ctrl+Shift+V instead; browsers restrict programmatic reads.',
      })
    }
  }, [pushToast])

  const toggleRecording = useCallback(async () => {
    if (!tab.sessionId) return
    try {
      const next = !recording
      await api.post(`/api/v1/sessions/${tab.sessionId}/recording`, { enabled: next })
      setRecording(next)
      pushToast({
        level: next ? 'warning' : 'info',
        title: next ? 'Recording started' : 'Recording stopped',
        message: next
          ? 'Everything in this session is being written to disk. Recordings routinely contain secrets.'
          : undefined,
      })
    } catch {
      pushToast({ level: 'error', title: 'Could not change recording state' })
    }
  }, [recording, tab.sessionId, pushToast])

  useEffect(() => {
    if (!searchOpen) return
    searchRef.current?.findNext(searchTerm, { incremental: true })
  }, [searchTerm, searchOpen])

  const frozen = tab.state === 'disconnected' || tab.state === 'failed' || tab.state === 'closed'

  return (
    <div className="flex h-full min-h-0 flex-col bg-surface-0">
      <div className="flex h-7 shrink-0 items-center gap-1 border-b border-border-subtle bg-surface-1 px-2">
        <ConnectionBadge state={connection} frozen={frozen} />
        <span className="ml-1 truncate font-mono text-sm text-text-secondary">{tab.hostName}</span>

        {recording && (
          <span className="ml-1">
            <Badge tone="danger">REC</Badge>
          </span>
        )}

        <div className="ml-auto flex items-center gap-0.5">
          <IconButton label="Copy selection" onClick={copySelection}>
            <ClipboardCopy className="h-3.5 w-3.5" />
          </IconButton>
          <IconButton label="Paste" onClick={paste}>
            <ClipboardPaste className="h-3.5 w-3.5" />
          </IconButton>
          <IconButton
            label="Search output"
            active={searchOpen}
            onClick={() => setSearchOpen((open) => !open)}
          >
            <Search className="h-3.5 w-3.5" />
          </IconButton>
          <IconButton label="Clear" onClick={() => termRef.current?.clear()}>
            <Eraser className="h-3.5 w-3.5" />
          </IconButton>
          <IconButton
            label={recording ? 'Stop recording' : 'Record session'}
            active={recording}
            onClick={toggleRecording}
          >
            {recording ? <VideoOff className="h-3.5 w-3.5" /> : <Video className="h-3.5 w-3.5" />}
          </IconButton>
          <IconButton
            label="Fullscreen"
            onClick={() => containerRef.current?.parentElement?.requestFullscreen?.()}
          >
            <Maximize2 className="h-3.5 w-3.5" />
          </IconButton>
        </div>
      </div>

      {searchOpen && (
        <div className="flex shrink-0 items-center gap-2 border-b border-border-subtle bg-surface-2 px-2 py-1">
          <Input
            value={searchTerm}
            onChange={(event) => setSearchTerm(event.target.value)}
            placeholder="Find in output"
            autoFocus
            className="h-6"
            onKeyDown={(event) => {
              if (event.key === 'Enter') {
                event.preventDefault()
                if (event.shiftKey) searchRef.current?.findPrevious(searchTerm)
                else searchRef.current?.findNext(searchTerm)
              }
              if (event.key === 'Escape') setSearchOpen(false)
            }}
          />
          <span className="shrink-0 text-xs text-text-muted">Enter next · Shift+Enter previous</span>
        </div>
      )}

      <div className="relative min-h-0 flex-1">
        <div ref={containerRef} className="absolute inset-0" />

        {/*
          A frozen pane must not accept keystrokes. A dead terminal that still
          echoes typing is how people come to believe they restarted a service
          when nothing happened.
        */}
        {frozen && (
          <div className="absolute inset-0 flex items-end justify-center bg-surface-0/40 backdrop-blur-[1px]">
            <div className="mb-8 rounded border border-border-strong bg-surface-3 px-3 py-2 text-center">
              <p className="text-base text-text-primary">Session ended</p>
              <p className="mt-0.5 max-w-xs text-sm text-text-secondary">
                {tab.exitReason ?? 'The connection closed.'}
              </p>
              <p className="mt-1 text-xs text-text-muted">
                Input is disabled. Reconnect from the tab menu to start a new session.
              </p>
            </div>
          </div>
        )}

        {connection === 'retrying' && !frozen && (
          <div className="absolute right-3 top-3 flex items-center gap-1.5 rounded border border-border-strong bg-surface-3 px-2 py-1 text-sm">
            <Circle className="h-2 w-2 animate-pulse-slow fill-accent text-accent" aria-hidden />
            <span className="text-text-secondary">Reconnecting…</span>
          </div>
        )}
      </div>
    </div>
  )
}

function ConnectionBadge({
  state,
  frozen,
}: {
  state: 'connecting' | 'open' | 'retrying' | 'closed'
  frozen: boolean
}) {
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
