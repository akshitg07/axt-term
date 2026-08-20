import { useMemo, useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { CornerDownLeft, Play, Search, Terminal as TerminalIcon } from 'lucide-react'

import { api, ApiError } from '@/lib/api'
import type { Snippet } from '@/lib/types'
import { useSnippetFolders, useSnippets } from '@/lib/hooks'
import { useActiveTab, useUI } from '@/lib/store'
import { Badge, Button, Dialog, EmptyState, Input } from '@/components/ui'
import { fuzzyFilter } from '@/lib/format'

interface RenderResponse {
  text: string
  run_mode: 'insert' | 'run'
  missing?: string[]
}

/**
 * The snippet library.
 *
 * Rendering and running are separate operations. A snippet resolves to text, the
 * text lands on the prompt, and the user presses Enter. Auto-run exists but is
 * opt-in per snippet, because a tool with root on fifty machines should not
 * execute on a single click by default.
 */
export function SnippetsPanel({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [query, setQuery] = useState('')
  const [vars, setVars] = useState<Record<string, string>>({})
  const [selected, setSelected] = useState<Snippet | null>(null)
  const [preview, setPreview] = useState<RenderResponse | null>(null)

  const snippetsQuery = useSnippets()
  const foldersQuery = useSnippetFolders()
  const tab = useActiveTab()
  const pushToast = useUI((s) => s.pushToast)

  const folderName = useMemo(() => {
    const map = new Map<string, string>()
    for (const folder of foldersQuery.data ?? []) map.set(folder.id, folder.name)
    return map
  }, [foldersQuery.data])

  const results = useMemo(
    () =>
      fuzzyFilter(
        snippetsQuery.data ?? [],
        query,
        (s) => `${s.name} ${s.description} ${s.body}`,
      ),
    [snippetsQuery.data, query],
  )

  const render = useMutation({
    mutationFn: (snippet: Snippet) =>
      api.post<RenderResponse>(`/api/v1/snippets/${snippet.id}/render`, {
        host_id: tab?.hostId,
        vars,
      }),
    onSuccess: (response) => setPreview(response),
    onError: (error) =>
      pushToast({
        level: 'error',
        title: 'Could not render the snippet',
        message: error instanceof ApiError ? error.message : undefined,
      }),
  })

  const choose = (snippet: Snippet) => {
    setSelected(snippet)
    setPreview(null)
    const initial: Record<string, string> = {}
    for (const variable of snippet.variables) {
      if (variable.default) initial[variable.name] = variable.default
    }
    setVars(initial)
    render.mutate(snippet)
  }

  // Insertion writes into the focused terminal by dispatching through the same
  // socket the terminal owns; the shell echoes it exactly as if typed.
  const insert = (text: string, run: boolean) => {
    if (!tab?.sessionId) {
      pushToast({
        level: 'warning',
        title: 'No session focused',
        message: 'Open a terminal tab first, then insert the snippet into it.',
      })
      return
    }
    window.dispatchEvent(
      new CustomEvent('axt:insert-into-terminal', {
        detail: { sessionId: tab.sessionId, text: run ? `${text}\n` : text },
      }),
    )
    onClose()
  }

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Snippets"
      description={
        tab ? `Insert into ${tab.hostName}` : 'Open a session to insert a snippet into it.'
      }
      width="lg"
      footer={
        <Button variant="ghost" onClick={onClose}>
          Close
        </Button>
      }
    >
      <div className="grid grid-cols-2 gap-4">
        <div className="min-w-0">
          <div className="relative mb-2">
            <Search
              className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-text-muted"
              aria-hidden
            />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter snippets"
              aria-label="Filter snippets"
              className="field h-6 pl-7"
              autoFocus
            />
          </div>

          {results.length === 0 ? (
            <EmptyState title="No snippets match" />
          ) : (
            <ul className="max-h-80 divide-y divide-border-subtle overflow-y-auto">
              {results.map((snippet) => (
                <li key={snippet.id}>
                  <button
                    onClick={() => choose(snippet)}
                    className={`w-full px-1 py-2 text-left ${
                      selected?.id === snippet.id ? 'bg-accent-muted/25' : 'hover:bg-surface-2'
                    }`}
                  >
                    <span className="flex items-center gap-1.5">
                      <span className="truncate text-base text-text-primary">{snippet.name}</span>
                      {snippet.run_mode === 'run' && <Badge tone="warning">auto-run</Badge>}
                    </span>
                    <span className="mt-0.5 block truncate text-sm text-text-secondary">
                      {snippet.description || snippet.body}
                    </span>
                    <span className="block text-xs text-text-muted">
                      {folderName.get(snippet.folder_id) ?? 'Uncategorised'} · used {snippet.use_count}×
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="min-w-0">
          {!selected ? (
            <EmptyState
              icon={<TerminalIcon className="h-6 w-6" />}
              title="Choose a snippet"
              message="Its variables and the resolved command appear here before anything is sent."
            />
          ) : (
            <div className="space-y-3">
              <div>
                <p className="text-base text-text-primary">{selected.name}</p>
                <p className="text-sm text-text-secondary">{selected.description}</p>
              </div>

              {selected.variables.length > 0 && (
                <div className="space-y-2">
                  {selected.variables.map((variable) => (
                    <Input
                      key={variable.name}
                      label={variable.label || variable.name}
                      value={vars[variable.name] ?? ''}
                      onChange={(e) => {
                        const next = { ...vars, [variable.name]: e.target.value }
                        setVars(next)
                      }}
                      onBlur={() => render.mutate(selected)}
                      placeholder={variable.default}
                    />
                  ))}
                </div>
              )}

              <div>
                <p className="label">Resolved command</p>
                <pre className="max-h-40 overflow-auto rounded border border-border-subtle bg-surface-0 p-2 font-mono text-sm text-text-primary">
                  {preview?.text ?? selected.body}
                </pre>
                {preview?.missing && preview.missing.length > 0 && (
                  <p className="mt-1 text-sm text-state-warning">
                    Still needs: {preview.missing.join(', ')}
                  </p>
                )}
              </div>

              <div className="flex gap-2">
                <Button
                  variant="primary"
                  icon={<CornerDownLeft className="h-3.5 w-3.5" />}
                  disabled={!preview || (preview.missing?.length ?? 0) > 0}
                  onClick={() => preview && insert(preview.text, false)}
                >
                  Insert
                </Button>
                <Button
                  variant="secondary"
                  icon={<Play className="h-3.5 w-3.5" />}
                  disabled={!preview || (preview.missing?.length ?? 0) > 0}
                  onClick={() => preview && insert(preview.text, true)}
                  title="Insert and press Enter"
                >
                  Insert and run
                </Button>
              </div>
              <p className="hint">
                Insert puts the command on the prompt so you can read it before it runs.
              </p>
            </div>
          )}
        </div>
      </div>
    </Dialog>
  )
}
