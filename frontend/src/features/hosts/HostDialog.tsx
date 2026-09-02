import { useEffect, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'

import { api, ApiError } from '@/lib/api'
import type { AuthMethod, Host, OSFamily, Protocol, RDPOptions } from '@/lib/types'
import { isDesktopProtocol, useCredentials, useFolders, useHosts } from '@/lib/hooks'
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
  rdp_options: RDPOptions
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
  rdp_options: {},
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
        rdp_options: existing.rdp_options ?? {},
      })
    } else {
      setForm(empty)
    }
  }, [open, existing])

  const set = <K extends keyof FormState>(key: K, value: FormState[K]) =>
    setForm((prev) => ({ ...prev, [key]: value }))

  /** Updates one field inside the desktop options. */
  const setOption = <K extends keyof RDPOptions>(key: K, value: RDPOptions[K]) =>
    setForm((prev) => ({ ...prev, rdp_options: { ...prev.rdp_options, [key]: value } }))

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

  // The same helper the sidebar and the shell use, so "is this a desktop?" has one
  // answer across the app rather than a protocol comparison repeated per file.
  const isDesktop = isDesktopProtocol(form.protocol)

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
          <option value="vnc">VNC</option>
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

        {isDesktop && (
          <DesktopOptions
            protocol={form.protocol}
            options={form.rdp_options}
            setOption={setOption}
          />
        )}
      </div>
    </Dialog>
  )
}

/**
 * Per-host RDP and VNC settings.
 *
 * Shown only for desktop protocols, because every field here is meaningless over
 * SSH. Clipboard and drive redirection lead the list and say what they open: each
 * is a bidirectional data path into the machine, and both are off until somebody
 * decides otherwise.
 */
function DesktopOptions({
  protocol,
  options,
  setOption,
}: {
  protocol: Protocol
  options: RDPOptions
  setOption: <K extends keyof RDPOptions>(key: K, value: RDPOptions[K]) => void
}) {
  const isRDP = protocol === 'rdp'

  return (
    <div className="col-span-2 space-y-3 border-t border-border-subtle pt-3">
      <p className="text-xs font-medium uppercase tracking-wider text-text-muted">
        {isRDP ? 'RDP options' : 'VNC options'}
      </p>

      <div className="space-y-2">
        <Checkbox
          label="Share the clipboard"
          hint="Copies text in both directions between your browser and the desktop. Off by default."
          checked={options.enable_clipboard ?? false}
          onChange={(e) => setOption('enable_clipboard', e.target.checked)}
        />
        {isRDP && (
          <>
            <Checkbox
              label="Redirect a drive"
              hint="Mounts a server-side directory as a drive on the desktop, which is a file path into the host. Off by default."
              checked={options.enable_drive ?? false}
              onChange={(e) => setOption('enable_drive', e.target.checked)}
            />
            <Checkbox
              label="Forward audio"
              checked={options.enable_audio ?? false}
              onChange={(e) => setOption('enable_audio', e.target.checked)}
            />
            <Checkbox
              label="Enable printing"
              checked={options.enable_printing ?? false}
              onChange={(e) => setOption('enable_printing', e.target.checked)}
            />
          </>
        )}
      </div>

      <div className="grid grid-cols-2 gap-3">
        {isRDP && options.enable_drive && (
          <div className="col-span-2">
            <Input
              label="Drive path on the server"
              value={options.drive_path ?? ''}
              onChange={(e) => setOption('drive_path', e.target.value)}
              placeholder="/var/lib/axt-term/drive"
              hint="Created if it does not exist. This directory is readable and writable from the desktop."
              spellCheck={false}
            />
          </div>
        )}

        {isRDP && (
          <>
            <Input
              label="Domain"
              value={options.domain ?? ''}
              onChange={(e) => setOption('domain', e.target.value)}
              placeholder="CORP"
              hint="Overrides the credential's domain for this host."
              spellCheck={false}
            />
            <Select
              label="Security mode"
              value={options.security ?? ''}
              onChange={(e) => setOption('security', e.target.value)}
            >
              <option value="">Negotiate</option>
              <option value="nla">NLA</option>
              <option value="nla-ext">NLA extended</option>
              <option value="tls">TLS</option>
              <option value="vmconnect">Hyper-V (vmconnect)</option>
              <option value="rdp">Legacy RDP</option>
            </Select>

            <Select
              label="Resize method"
              value={options.resize_method ?? ''}
              onChange={(e) => setOption('resize_method', e.target.value)}
            >
              <option value="">Display update (recommended)</option>
              <option value="display-update">Display update</option>
              <option value="reconnect">Reconnect</option>
            </Select>
            <Input
              label="Keyboard layout"
              value={options.server_layout ?? ''}
              onChange={(e) => setOption('server_layout', e.target.value)}
              placeholder="en-us-qwerty"
              hint="A wrong layout moves the punctuation, which usually shows up as a rejected password."
              spellCheck={false}
            />
          </>
        )}

        {!isRDP && (
          <>
            <Select
              label="Cursor"
              value={options.cursor ?? ''}
              onChange={(e) => setOption('cursor', e.target.value)}
            >
              <option value="">Server default</option>
              <option value="remote">Drawn by the server</option>
              <option value="local">Drawn locally</option>
            </Select>
            <Select
              label="Clipboard encoding"
              value={options.clipboard_encoding ?? ''}
              onChange={(e) => setOption('clipboard_encoding', e.target.value)}
            >
              <option value="">Server default</option>
              <option value="UTF-8">UTF-8</option>
              <option value="ISO8859-1">ISO8859-1</option>
              <option value="CP1252">CP1252</option>
              <option value="ISO8859-2">ISO8859-2</option>
            </Select>
          </>
        )}

        <Select
          label="Colour depth"
          value={String(options.color_depth ?? '')}
          onChange={(e) =>
            setOption('color_depth', e.target.value ? Number(e.target.value) : undefined)
          }
        >
          <option value="">Server default</option>
          <option value="8">8-bit (256 colours)</option>
          <option value="16">16-bit</option>
          <option value="24">24-bit</option>
          <option value="32">32-bit</option>
        </Select>
        <div className="grid grid-cols-2 gap-2">
          <Input
            label="Initial width"
            type="number"
            value={options.initial_width ?? ''}
            onChange={(e) =>
              setOption('initial_width', e.target.value ? Number(e.target.value) : undefined)
            }
            placeholder="auto"
          />
          <Input
            label="Initial height"
            type="number"
            value={options.initial_height ?? ''}
            onChange={(e) =>
              setOption('initial_height', e.target.value ? Number(e.target.value) : undefined)
            }
            placeholder="auto"
          />
        </div>
      </div>

      <div className="space-y-2">
        {isRDP ? (
          <>
            <Checkbox
              label="Trust any certificate"
              hint="Skips certificate validation. Reasonable for a self-signed host you control, and a hole on any network you do not."
              checked={options.ignore_cert ?? false}
              onChange={(e) => setOption('ignore_cert', e.target.checked)}
            />
            <Checkbox
              label="Hide the desktop wallpaper"
              hint="Saves bandwidth on a slow link."
              checked={options.disable_wallpaper ?? false}
              onChange={(e) => setOption('disable_wallpaper', e.target.checked)}
            />
            <Checkbox
              label="Enable theming"
              checked={options.enable_theming ?? false}
              onChange={(e) => setOption('enable_theming', e.target.checked)}
            />
            <Checkbox
              label="Enable font smoothing"
              checked={options.enable_font_smoothing ?? false}
              onChange={(e) => setOption('enable_font_smoothing', e.target.checked)}
            />
            <Checkbox
              label="Connect to the console session"
              hint="Attaches to the Windows admin session rather than starting a new one."
              checked={options.console ?? false}
              onChange={(e) => setOption('console', e.target.checked)}
            />
          </>
        ) : (
          <>
            <Checkbox
              label="Swap red and blue"
              hint="Corrects a server that reports its pixel order wrongly, which looks like a blue-tinted desktop."
              checked={options.swap_red_blue ?? false}
              onChange={(e) => setOption('swap_red_blue', e.target.checked)}
            />
            <Checkbox
              label="View only"
              hint="Watches without sending keyboard or mouse input."
              checked={options.read_only ?? false}
              onChange={(e) => setOption('read_only', e.target.checked)}
            />
          </>
        )}
      </div>
    </div>
  )
}
