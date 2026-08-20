import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { KeyRound, Plus, ShieldCheck, Trash2 } from 'lucide-react'

import { api, ApiError } from '@/lib/api'
import type { Credential, CredentialKind } from '@/lib/types'
import { useCredentials } from '@/lib/hooks'
import { useUI } from '@/lib/store'
import {
  Badge,
  Button,
  Dialog,
  EmptyState,
  IconButton,
  Input,
  Select,
  Textarea,
  useConfirm,
} from '@/components/ui'
import { formatRelative } from '@/lib/format'

/**
 * Credential profiles.
 *
 * Note what this screen cannot do: read a secret back. The API has no endpoint for
 * it and the response type has no field for it, so the UI shows a fingerprint and
 * a "password set" marker instead. Rotating means typing a new value, never
 * revealing the old one.
 */
export function CredentialsPanel({ open, onClose }: { open: boolean; onClose: () => void }) {
  const query = useCredentials()
  const [editorOpen, setEditorOpen] = useState(false)
  const [editing, setEditing] = useState<Credential | null>(null)
  const confirm = useConfirm()
  const queryClient = useQueryClient()
  const pushToast = useUI((s) => s.pushToast)

  const remove = useMutation({
    mutationFn: (credential: Credential) =>
      api.del(`/api/v1/credentials/${credential.id}${credential.in_use_by_count > 0 ? '?force=true' : ''}`),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['credentials'] })
      await queryClient.invalidateQueries({ queryKey: ['hosts'] })
      pushToast({ level: 'success', title: 'Credential deleted' })
    },
    onError: (error) =>
      pushToast({
        level: 'error',
        title: 'Could not delete the credential',
        message: error instanceof ApiError ? error.message : undefined,
      }),
  })

  const confirmDelete = async (credential: Credential) => {
    const inUse = credential.in_use_by_count
    const ok = await confirm({
      title: `Delete ${credential.name}?`,
      destructive: true,
      confirmLabel: 'Delete credential',
      message: inUse
        ? `${inUse} host${inUse === 1 ? '' : 's'} reference this credential. They will keep their configuration but lose their stored secret, so connections will fail until another credential is attached.`
        : 'The stored secret is destroyed. This cannot be undone.',
    })
    if (ok) remove.mutate(credential)
  }

  return (
    <>
      <Dialog
        open={open}
        onClose={onClose}
        title="Credentials"
        description="Secrets are encrypted with a key held outside the database and are never returned to the browser."
        width="lg"
        footer={
          <>
            <Button variant="ghost" onClick={onClose}>
              Close
            </Button>
            <Button
              variant="primary"
              icon={<Plus className="h-3.5 w-3.5" />}
              onClick={() => {
                setEditing(null)
                setEditorOpen(true)
              }}
            >
              New credential
            </Button>
          </>
        }
      >
        {(query.data?.length ?? 0) === 0 ? (
          <EmptyState
            icon={<KeyRound className="h-6 w-6" />}
            title="No credentials yet"
            message="Add an SSH key or a password so hosts can authenticate without prompting."
          />
        ) : (
          <ul className="divide-y divide-border-subtle">
            {(query.data ?? []).map((credential) => (
              <li key={credential.id} className="flex items-start gap-3 py-2.5">
                <KeyRound className="mt-0.5 h-4 w-4 shrink-0 text-text-muted" aria-hidden />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="text-base text-text-primary">{credential.name}</span>
                    <Badge>{credential.kind.replace('_', ' ')}</Badge>
                    {credential.has_password && <Badge tone="accent">password set</Badge>}
                    {credential.has_private_key && <Badge tone="accent">key set</Badge>}
                    {credential.has_passphrase && <Badge tone="accent">passphrase set</Badge>}
                  </div>
                  <p className="mt-0.5 truncate text-sm text-text-secondary">
                    {credential.username || 'no username'}
                    {credential.key_fingerprint && ` · ${credential.key_type} ${credential.key_fingerprint}`}
                  </p>
                  <p className="text-xs text-text-muted">
                    used by {credential.in_use_by_count} host
                    {credential.in_use_by_count === 1 ? '' : 's'} · last used{' '}
                    {formatRelative(credential.last_used_at)}
                  </p>
                </div>
                <div className="flex shrink-0 gap-0.5">
                  <IconButton
                    label={`Edit ${credential.name}`}
                    onClick={() => {
                      setEditing(credential)
                      setEditorOpen(true)
                    }}
                  >
                    <ShieldCheck className="h-3.5 w-3.5" />
                  </IconButton>
                  <IconButton
                    label={`Delete ${credential.name}`}
                    onClick={() => void confirmDelete(credential)}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </IconButton>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Dialog>

      <CredentialEditor
        open={editorOpen}
        credential={editing}
        onClose={() => setEditorOpen(false)}
      />
    </>
  )
}

function CredentialEditor({
  open,
  credential,
  onClose,
}: {
  open: boolean
  credential: Credential | null
  onClose: () => void
}) {
  const queryClient = useQueryClient()
  const pushToast = useUI((s) => s.pushToast)
  const [name, setName] = useState('')
  const [kind, setKind] = useState<CredentialKind>('ssh_key')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [privateKey, setPrivateKey] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [notes, setNotes] = useState('')
  const [errors, setErrors] = useState<Record<string, string>>({})

  // Reset when the dialog opens, so a previously typed secret is never carried
  // into a different credential.
  const [lastOpen, setLastOpen] = useState(false)
  if (open !== lastOpen) {
    setLastOpen(open)
    if (open) {
      setName(credential?.name ?? '')
      setKind(credential?.kind ?? 'ssh_key')
      setUsername(credential?.username ?? '')
      setNotes(credential?.notes ?? '')
      setPassword('')
      setPrivateKey('')
      setPassphrase('')
      setErrors({})
    }
  }

  const save = useMutation({
    mutationFn: () => {
      if (credential) {
        // Only fields the user actually touched are sent: omitting a secret means
        // leave it unchanged, which is what lets an edit not clear a password.
        const body: Record<string, unknown> = { name, username, notes }
        if (password) body.password = password
        if (privateKey) body.private_key = privateKey
        if (passphrase) body.passphrase = passphrase
        return api.patch(`/api/v1/credentials/${credential.id}`, body)
      }
      return api.post('/api/v1/credentials', {
        name,
        kind,
        username,
        notes,
        password: password || undefined,
        private_key: privateKey || undefined,
        passphrase: passphrase || undefined,
      })
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['credentials'] })
      pushToast({ level: 'success', title: credential ? 'Credential updated' : 'Credential created' })
      onClose()
    },
    onError: (error) => {
      if (error instanceof ApiError) {
        setErrors(error.fields)
        if (Object.keys(error.fields).length === 0) {
          pushToast({ level: 'error', title: 'Could not save', message: error.message })
        }
      }
    },
  })

  const wantsKey = kind === 'ssh_key'
  const wantsPassword = kind === 'password' || kind === 'rdp_password'

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={credential ? `Edit ${credential.name}` : 'New credential'}
      description={
        credential
          ? 'Leave a secret field blank to keep the stored value.'
          : 'Secrets are encrypted before they touch the database.'
      }
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" loading={save.isPending} disabled={!name} onClick={() => save.mutate()}>
            Save
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <Input label="Name" value={name} error={errors.name} onChange={(e) => setName(e.target.value)} autoFocus />

        {!credential && (
          <Select label="Kind" value={kind} onChange={(e) => setKind(e.target.value as CredentialKind)}>
            <option value="ssh_key">SSH private key</option>
            <option value="password">Password</option>
            <option value="rdp_password">Windows / RDP password</option>
            <option value="ssh_agent">SSH agent</option>
          </Select>
        )}

        <Input
          label="Username"
          value={username}
          error={errors.username}
          onChange={(e) => setUsername(e.target.value)}
          spellCheck={false}
        />

        {(wantsPassword || credential?.has_password) && (
          <Input
            label="Password"
            type="password"
            value={password}
            error={errors.password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder={credential?.has_password ? '•••••••• (unchanged)' : ''}
            autoComplete="new-password"
          />
        )}

        {(wantsKey || credential?.has_private_key) && (
          <>
            <Textarea
              label="Private key (PEM)"
              value={privateKey}
              error={errors.private_key}
              onChange={(e) => setPrivateKey(e.target.value)}
              rows={6}
              placeholder={
                credential?.has_private_key
                  ? '(unchanged — paste a new key to replace it)'
                  : '-----BEGIN OPENSSH PRIVATE KEY-----'
              }
              spellCheck={false}
              hint="Stored encrypted. Only its fingerprint is ever displayed again."
            />
            <Input
              label="Key passphrase"
              type="password"
              value={passphrase}
              error={errors.passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              placeholder={credential?.has_passphrase ? '•••••••• (unchanged)' : 'Only if the key is encrypted'}
              autoComplete="new-password"
            />
          </>
        )}

        <Textarea label="Notes" value={notes} onChange={(e) => setNotes(e.target.value)} rows={2} />
      </div>
    </Dialog>
  )
}
