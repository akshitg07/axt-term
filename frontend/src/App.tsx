import { useEffect } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, CheckCircle2, Info, X, XCircle } from 'lucide-react'
import clsx from 'clsx'

import { api, ApiError, setUnauthorizedHandler } from './lib/api'
import type { MeResponse } from './lib/types'
import { useUI } from './lib/store'
import { ConfirmProvider, Spinner } from './components/ui'
import { LoginScreen } from './features/auth/LoginScreen'
import { ChangePasswordScreen } from './features/auth/ChangePasswordScreen'
import { Shell } from './app/Shell'
import { useEventStream } from './lib/hooks'

export function App() {
  const queryClient = useQueryClient()

  // The session lives in an HttpOnly cookie, so "am I signed in" is a question
  // only the server can answer. Asking it is the app's first action.
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['me'],
    queryFn: () => api.get<MeResponse>('/api/v1/auth/me'),
    retry: false,
    staleTime: 60_000,
  })

  useEffect(() => {
    // When any request reports the session is gone, drop cached data so the login
    // screen cannot render behind stale inventory.
    setUnauthorizedHandler(() => {
      queryClient.setQueryData(['me'], null)
      queryClient.clear()
    })
    return () => setUnauthorizedHandler(null)
  }, [queryClient])

  if (isLoading) {
    return (
      <div className="flex h-full items-center justify-center bg-surface-0">
        <Spinner className="h-5 w-5" />
      </div>
    )
  }

  const unauthenticated =
    !data || (isError && error instanceof ApiError && error.status === 401) || isError

  if (unauthenticated) {
    return <LoginScreen />
  }

  // A generated or administratively-reset password must be changed before the
  // account can be used; the server enforces this too, and this screen is what
  // makes the enforcement navigable rather than a wall of 403s.
  if (data.user.must_change_password) {
    return <ChangePasswordScreen user={data.user} />
  }

  return (
    <ConfirmProvider>
      <AuthenticatedApp me={data} />
    </ConfirmProvider>
  )
}

function AuthenticatedApp({ me }: { me: MeResponse }) {
  useEventStream()

  return (
    <>
      <Shell me={me} />
      <Toasts />
    </>
  )
}

function Toasts() {
  const toasts = useUI((s) => s.toasts)
  const dismiss = useUI((s) => s.dismissToast)

  if (toasts.length === 0) return null

  const icons = {
    info: <Info className="h-4 w-4 text-state-info" aria-hidden />,
    success: <CheckCircle2 className="h-4 w-4 text-state-success" aria-hidden />,
    warning: <AlertTriangle className="h-4 w-4 text-state-warning" aria-hidden />,
    error: <XCircle className="h-4 w-4 text-state-danger" aria-hidden />,
  }

  return (
    <div
      className="pointer-events-none fixed bottom-8 right-3 z-40 flex w-80 flex-col gap-2"
      // Announced so a completed transfer or a failed connection reaches a screen
      // reader without stealing focus.
      role="status"
      aria-live="polite"
    >
      {toasts.map((toast) => (
        <div
          key={toast.id}
          className={clsx(
            'pointer-events-auto flex items-start gap-2 rounded border bg-surface-3 px-3 py-2 animate-slide-up',
            toast.level === 'error' ? 'border-state-danger/50' : 'border-border-strong',
          )}
          style={{ boxShadow: 'var(--shadow)' }}
        >
          {icons[toast.level]}
          <div className="min-w-0 flex-1">
            <p className="text-base text-text-primary">{toast.title}</p>
            {toast.message && (
              <p className="mt-0.5 break-words text-sm text-text-secondary">{toast.message}</p>
            )}
          </div>
          <button
            onClick={() => dismiss(toast.id)}
            aria-label="Dismiss"
            className="text-text-muted hover:text-text-primary"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      ))}
    </div>
  )
}
