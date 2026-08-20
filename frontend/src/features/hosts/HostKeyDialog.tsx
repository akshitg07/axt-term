import { ShieldAlert, ShieldQuestion } from 'lucide-react'

import { useHostKeyPrompt, useHosts, useTrustHostKey } from '@/lib/hooks'
import { Button, Dialog } from '@/components/ui'

/**
 * Trust-on-first-use prompt.
 *
 * The fingerprint shown is the one the *server* observed, and accepting trusts
 * exactly that — the client cannot supply a fingerprint of its own. Verifying out
 * of band is the whole point, so the dialog says how rather than just asking for
 * a click.
 */
export function HostKeyDialog() {
  const prompt = useHostKeyPrompt((s) => s.prompt)
  const clear = useHostKeyPrompt((s) => s.clear)
  const trust = useTrustHostKey()
  const hostsQuery = useHosts()

  if (!prompt) return null
  const host = hostsQuery.data?.find((h) => h.id === prompt.hostId)

  return (
    <Dialog
      open
      onClose={clear}
      title="Unrecognised host key"
      description={`${prompt.hostName} · ${prompt.hostname}:${prompt.port}`}
      width="md"
      footer={
        <>
          <Button variant="ghost" onClick={clear}>
            Cancel
          </Button>
          <Button
            variant="primary"
            loading={trust.isPending}
            disabled={!host}
            onClick={() =>
              host &&
              trust.mutate({ hostId: prompt.hostId, fingerprint: prompt.fingerprint, host })
            }
          >
            Trust and connect
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <div className="flex items-start gap-2 rounded border border-state-warning/40 bg-state-warning/10 px-2.5 py-2">
          <ShieldQuestion className="mt-px h-4 w-4 shrink-0 text-state-warning" aria-hidden />
          <p className="text-base text-text-secondary">
            AXT-Term has not seen this host before, so it cannot tell you whether the
            key is genuine. Trusting it pins the key: any future change will be
            refused until an administrator revokes it.
          </p>
        </div>

        <dl className="space-y-1.5 rounded border border-border-subtle bg-surface-2 p-2.5">
          <div className="flex gap-2">
            <dt className="w-24 shrink-0 text-sm text-text-muted">Key type</dt>
            <dd className="font-mono text-base text-text-primary">{prompt.key_type}</dd>
          </div>
          <div className="flex gap-2">
            <dt className="w-24 shrink-0 text-sm text-text-muted">Fingerprint</dt>
            <dd className="break-all font-mono text-base text-accent">{prompt.fingerprint}</dd>
          </div>
        </dl>

        <div className="space-y-1 text-sm text-text-secondary">
          <p className="text-text-primary">Verify it before accepting</p>
          <p>
            On the host itself, run{' '}
            <code className="rounded bg-surface-2 px-1 font-mono text-text-primary">
              ssh-keygen -lf /etc/ssh/ssh_host_{prompt.key_type.replace('ssh-', '')}_key.pub
            </code>{' '}
            and compare. A provisioning log or a console session is equally good.
          </p>
        </div>

        {!host && (
          <p className="flex items-center gap-1.5 text-sm text-state-danger">
            <ShieldAlert className="h-3.5 w-3.5" aria-hidden />
            The host record is no longer available; reload and try again.
          </p>
        )}
      </div>
    </Dialog>
  )
}
