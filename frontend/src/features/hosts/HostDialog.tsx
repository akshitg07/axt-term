import { useEffect, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'

import { api, ApiError } from '@/lib/api'
import type { AuthMethod, Host, OSFamily, Protocol } from '@/lib/types'
import { useCredentials, useFolders, useHosts } from '@/lib/hooks'
import { useUI } from '@/lib/store'
import { Button, Checkbox, Dialog, Input, Select, Textarea } from '@/components/ui'

const DEFAULT_PORTS: Record<string, number> = { ssh: 22, sftp: 22, rdp: 3389, vnc: 5900, telnet: 23, winrm: 5986 }

interface HostDialogProps {
  open: boolean
  hostId: string | null
  onClose: () => void
}

interface FormState {
  name: string
  hostname: string
  port: number
  protocol: Protocol
  folder_id: string
  username: string
  auth_method: AuthMethod
  credential_id: string
  jump_host_id: string
  os_family: OSFamily
  color: string
  notes: string
  is_favorite: boolean
  health_check_enabled: boolean
  tags: string
}

const empty: FormState = {
  name: '',
  hostname: '',
  port: 22,
  protocol: 'ssh',
  folder_id: '',
  username: '',
  auth_method: 'credential',
  credential_id: '',
  jump_host_id: '',
  os_family: 'linux',
  color: '',
  notes: '',
  is_favorite: false,
  health_check_enabled: false,
  tags: '',
}

export function HostDialog({ open, hostId, onClose }: HostDialogProps) {
  const queryClient = useQueryClient()
  const pushToast = useUI((s) => s.pushToast)
  const foldersQuery = useFolders()
  const credentialsQuery = useCredentials()
  const hostsQuery = useHosts()

  const [form, setForm] = useState<FormState>(empty)
  const [errors, setErrors] = useState<Record<string, string>>({})

  const existing = hostId ? hostsQuery.data?.find((h) => h.id === hostId) : undefined

  useEffect(() => {
    if (!open) return
    setErrors({})
    if (existing) {
      setForm({
        name: existing.name,
        hostname: existing.hostname,
        port: existing.port,
        protocol: existing.protocol,
        folder_id: existing.folder_id,
        username: existing.username,
        auth_method: existing.auth_method,
        credential_id: existing.credential_id,
        jump_host_id: existing.jump_host_id,
        os_family: existing.os_family,
        color: existing.color,
        notes: existing.notes,
        is_favorite: existing.is_favorite,
        health_check_enabled: existing.health_check_enabled,
        tags: existing.tags.join(', '),
      })
    } else {
      setForm(empty)
    }
  }, [open, existing])

  const set = <K extends keyof FormState>(key: K, value: FormState[K]) =>
    setForm((prev) => ({ ...prev, [key]: value }))

  const save = useMutation({
    mutationFn: async () => {
      const body = {
        ...form,
        tags: form.tags
          .split(',')
          .map((t) => t.trim())
          .filter(Boolean),
      }
      if (hostId) return api.patch<Host>(`/api/v1/hosts/${hostId}`, body)
      return api.post<Host>('/api/v1/hosts', body)
    },
    onSuccess: async (host) => {
      await queryClient.invalidateQueries({ queryKey: ['hosts'] })
      pushToast({ level: 'success', title: hostId ? `Updated ${host.name}` : `Added ${host.name}` })
      onClose()
    },
    onError: (error) => {
      if (error instanceof ApiError) {
        setErrors(error.fields)
        if (Object.keys(error.fields).length === 0) {
          pushToast({ level: 'error', title: 'Could not save the host', message: error.message })
        }
      }
    },
  })

  // Changing protocol moves the port to that protocol's default, but only when the
  // current value is still a default -- so a deliberately custom port survives.
  const changeProtocol = (protocol: Protocol) => {
    const wasDefault = Object.values(DEFAULT_PORTS).includes(form.port)
    set('protocol', protocol)
    if (wasDefault) set('port', DEFAULT_PORTS[protocol] ?? form.port)
  }

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={hostId ? 'Edit host' : 'Add host'}
      description={hostId ? existing?.hostname : 'Add a machine to the inventory.'}
      width="lg"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="primary"
            loading={save.isPending}
            disabled={!form.name || !form.hostname}
            onClick={() => save.mutate()}
          >
            {hostId ? 'Save changes' : 'Add host'}
          </Button>
        </>
      }
    >
      <div className="grid grid-cols-2 gap-3">
        <Input
          label="Name"
          value={form.name}
          error={errors.name}
          onChange={(e) => set('name', e.target.value)}
          placeholder="prod-web01"
          autoFocus
        />
        <Input
          label="Hostname or IP"
          value={form.hostname}
          error={errors.hostname}
          onChange={(e) => set('hostname', e.target.value)}
          placeholder="10.0.4.11"
          spellCheck={false}
        />

        <Select
          label="Protocol"
          value={form.protocol}
          onChange={(e) => changeProtocol(e.target.value as Protocol)}
        >
          <option value="ssh">SSH</option>
          <option value="sftp">SFTP</option>
          <option value="rdp">RDP</option>
          <option value="vnc">VNC (coming soon)</option>
          <option value="telnet">Telnet (coming soon)</option>
          <option value="winrm">WinRM (coming soon)</option>
        </Select>
        <Input
          label="Port"
          type="number"
          value={form.port}
          error={errors.port}
          onChange={(e) => set('port', Number(e.target.value))}
        />

        <Input
          label="Username"
          value={form.username}
          error={errors.username}
          onChange={(e) => set('username', e.target.value)}
          hint="Overrides the credential's username when set."
          spellCheck={false}
        />
        <Select
          label="Authentication"
          value={form.auth_method}
          onChange={(e) => set('auth_method', e.target.value as AuthMethod)}
        >
          <option value="credential">Credential profile</option>
          <option value="agent">SSH agent</option>
          <option value="password_prompt">Ask each time (coming soon)</option>
        </Select>

        <Select
          label="Credential"
          value={form.credential_id}
          onChange={(e) => set('credential_id', e.target.value)}
          error={errors.credential_id}
        >
          <option value="">None</option>
          {(credentialsQuery.data ?? []).map((credential) => (
            <option key={credential.id} value={credential.id}>
              {credential.name}
              {credential.key_fingerprint ? ` · ${credential.key_type}` : ''}
            </option>
          ))}
        </Select>
        <Select
          label="Jump host"
          value={form.jump_host_id}
          onChange={(e) => set('jump_host_id', e.target.value)}
          error={errors.jump_host_id}
        >
          <option value="">Direct connection</option>
          {(hostsQuery.data ?? [])
            .filter((h) => h.id !== hostId)
            .map((h) => (
              <option key={h.id} value={h.id}>
                {h.name}
              </option>
            ))}
        </Select>

        <Select
          label="Folder"
          value={form.folder_id}
          onChange={(e) => set('folder_id', e.target.value)}
        >
          <option value="">No folder</option>
          {(foldersQuery.data ?? []).map((folder) => (
            <option key={folder.id} value={folder.id}>
              {folder.path ?? folder.name}
            </option>
          ))}
        </Select>
        <Select
          label="Operating system"
          value={form.os_family}
          onChange={(e) => set('os_family', e.target.value as OSFamily)}
        >
          <option value="linux">Linux</option>
          <option value="windows">Windows</option>
          <option value="bsd">BSD</option>
          <option value="macos">macOS</option>
          <option value="network">Network device</option>
          <option value="unknown">Unknown</option>
        </Select>

        <Input
          label="Tags"
          value={form.tags}
          error={errors.tags}
          onChange={(e) => set('tags', e.target.value)}
          hint="Comma separated. Created automatically if new."
        />
        <Input
          label="Colour"
          value={form.color}
          error={errors.color}
          onChange={(e) => set('color', e.target.value)}
          placeholder="#22d3ee"
          hint="Shown as a stripe in the sidebar."
        />

        <div className="col-span-2">
          <Textarea
            label="Notes"
            value={form.notes}
            onChange={(e) => set('notes', e.target.value)}
            rows={2}
            hint="Searchable. Useful for a ticket reference or an escalation path."
          />
        </div>

        <div className="col-span-2 space-y-2 border-t border-border-subtle pt-3">
          <Checkbox
            label="Favourite"
            checked={form.is_favorite}
            onChange={(e) => set('is_favorite', e.target.checked)}
          />
          <Checkbox
            label="Check reachability periodically"
            hint="Off by default. Enabling it opens a TCP connection every five minutes; it never authenticates."
            checked={form.health_check_enabled}
            onChange={(e) => set('health_check_enabled', e.target.checked)}
          />
        </div>
      </div>
    </Dialog>
  )
}
