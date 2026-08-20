import { useState, type FormEvent } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ShieldAlert } from 'lucide-react'

import { api, ApiError } from '@/lib/api'
import { Button, Input } from '@/components/ui'
import { Wordmark } from '@/components/Wordmark'

interface LoginResponse {
  user: { id: string; username: string }
  expires_at: string
}

export function LoginScreen() {
  const queryClient = useQueryClient()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [message, setMessage] = useState('')

  const login = useMutation({
    mutationFn: () =>
      api.post<LoginResponse>('/api/v1/auth/login', { username, password }, { quiet: true }),
    onSuccess: async () => {
      setMessage('')
      // Refetch identity rather than trusting the login response, so permissions
      // and the must-change-password flag come from one authority.
      await queryClient.invalidateQueries({ queryKey: ['me'] })
    },
    onError: (error) => {
      if (error instanceof ApiError) {
        setMessage(error.message)
      } else {
        setMessage('Could not sign in. Check your connection and try again.')
      }
      setPassword('')
    },
  })

  const submit = (event: FormEvent) => {
    event.preventDefault()
    if (!username || !password) return
    login.mutate()
  }

  return (
    <div className="flex h-full items-center justify-center bg-surface-0 px-4">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center gap-2">
          <Wordmark className="h-7" />
          <p className="text-sm text-text-muted">Your remote infrastructure, one terminal away.</p>
        </div>

        <form onSubmit={submit} className="panel space-y-3 p-4">
          <Input
            label="Username"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            autoComplete="username"
            autoFocus
            required
            spellCheck={false}
          />
          <Input
            label="Password"
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="current-password"
            required
          />

          {message && (
            <div
              role="alert"
              className="flex items-start gap-2 rounded border border-state-danger/40 bg-state-danger/10 px-2.5 py-2 text-sm text-text-primary"
            >
              <ShieldAlert className="mt-px h-3.5 w-3.5 shrink-0 text-state-danger" aria-hidden />
              <span>{message}</span>
            </div>
          )}

          <Button
            type="submit"
            variant="primary"
            className="w-full"
            loading={login.isPending}
            disabled={!username || !password}
          >
            Sign in
          </Button>
        </form>

        <p className="mt-4 text-center text-sm text-text-muted">
          No account yet? Create the first administrator on the server with{' '}
          <code className="rounded bg-surface-2 px-1 text-text-secondary">
            axt-admin user create
          </code>
        </p>
      </div>
    </div>
  )
}
