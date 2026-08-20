import { useState, type FormEvent } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { KeyRound } from 'lucide-react'

import { api, ApiError } from '@/lib/api'
import type { User } from '@/lib/types'
import { Button, Input } from '@/components/ui'
import { Wordmark } from '@/components/Wordmark'

/**
 * Shown when an account is flagged must-change-password: a generated bootstrap
 * password, or one an administrator reset.
 *
 * The server blocks every other endpoint until this is done, so this screen is
 * what makes that enforcement navigable instead of an unexplained wall of 403s.
 */
export function ChangePasswordScreen({ user }: { user: User }) {
  const queryClient = useQueryClient()
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})
  const [message, setMessage] = useState('')

  const change = useMutation({
    mutationFn: () =>
      api.post<void>('/api/v1/auth/password', {
        current_password: current,
        new_password: next,
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['me'] })
    },
    onError: (error) => {
      if (error instanceof ApiError) {
        setFieldErrors(error.fields)
        if (Object.keys(error.fields).length === 0) setMessage(error.message)
      } else {
        setMessage('Could not change the password. Try again.')
      }
    },
  })

  const mismatch = confirm.length > 0 && next !== confirm
  const canSubmit = current.length > 0 && next.length >= 12 && !mismatch

  const submit = (event: FormEvent) => {
    event.preventDefault()
    setMessage('')
    setFieldErrors({})
    if (canSubmit) change.mutate()
  }

  return (
    <div className="flex h-full items-center justify-center bg-surface-0 px-4">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center gap-2">
          <Wordmark className="h-7" />
        </div>

        <form onSubmit={submit} className="panel space-y-3 p-4">
          <div className="flex items-start gap-2 rounded border border-accent/40 bg-accent-muted/20 px-2.5 py-2 text-sm">
            <KeyRound className="mt-px h-3.5 w-3.5 shrink-0 text-accent" aria-hidden />
            <span className="text-text-secondary">
              Signed in as <strong className="text-text-primary">{user.username}</strong>. Choose a
              new password before continuing.
            </span>
          </div>

          <Input
            label="Current password"
            type="password"
            value={current}
            onChange={(event) => setCurrent(event.target.value)}
            error={fieldErrors.current_password}
            autoComplete="current-password"
            autoFocus
            required
          />
          <Input
            label="New password"
            type="password"
            value={next}
            onChange={(event) => setNext(event.target.value)}
            error={fieldErrors.new_password}
            hint="At least 12 characters. Length matters more than symbols."
            autoComplete="new-password"
            required
          />
          <Input
            label="Confirm new password"
            type="password"
            value={confirm}
            onChange={(event) => setConfirm(event.target.value)}
            error={mismatch ? 'The two passwords do not match' : undefined}
            autoComplete="new-password"
            required
          />

          {message && (
            <p role="alert" className="text-sm text-state-danger">
              {message}
            </p>
          )}

          <p className="hint">
            Changing your password signs out every other browser session, including
            any an attacker might hold.
          </p>

          <Button
            type="submit"
            variant="primary"
            className="w-full"
            loading={change.isPending}
            disabled={!canSubmit}
          >
            Set password and continue
          </Button>
        </form>
      </div>
    </div>
  )
}
