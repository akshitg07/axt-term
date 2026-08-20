import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

import './styles/index.css'
import { App } from './App'
import { applyStoredTheme } from './lib/store'
import { ApiError } from './lib/api'

// Applied before first paint so the app never flashes the wrong theme.
applyStoredTheme()

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Inventory changes when a person edits it, not on a timer. Refetching on
      // window focus would produce constant requests for a tool that stays open
      // all day.
      refetchOnWindowFocus: false,
      staleTime: 30_000,
      retry: (failureCount, error) => {
        // Never retry a rejection: a 403 or a 404 will not become a 200, and
        // retrying an auth failure just delays the login redirect.
        if (error instanceof ApiError && error.status >= 400 && error.status < 500) return false
        return failureCount < 2
      },
    },
    mutations: { retry: false },
  },
})

const container = document.getElementById('root')
if (!container) throw new Error('root element is missing from index.html')

createRoot(container).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </StrictMode>,
)
