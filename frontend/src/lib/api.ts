/**
 * Typed API client.
 *
 * Three things it guarantees, so no caller has to remember them:
 *
 *  - The CSRF token is read from the cookie and sent on every state-changing
 *    request. Forgetting it produces a 403 that looks like a permissions bug, so
 *    it is handled here rather than per call site.
 *  - Errors always arrive as ApiError with the server's stable `code`, so UI code
 *    switches on a machine-readable value instead of matching on message text.
 *  - Nothing is ever stored in localStorage. The session lives in an HttpOnly
 *    cookie; there is no token here for injected script to steal.
 */

export const CSRF_COOKIE = 'axt_csrf'
export const CSRF_COOKIE_SECURE = '__Host-axt_csrf'
export const CSRF_HEADER = 'X-AXT-CSRF'

/** Error codes the UI branches on. Mirrors the Go constants in httpx. */
export type ErrorCode =
  | 'bad_request'
  | 'validation_failed'
  | 'unauthenticated'
  | 'forbidden'
  | 'csrf_failed'
  | 'origin_rejected'
  | 'not_found'
  | 'method_not_allowed'
  | 'conflict'
  | 'confirmation_required'
  | 'account_locked'
  | 'payload_too_large'
  | 'unsupported_media_type'
  | 'rate_limited'
  | 'internal_error'
  | 'not_implemented'
  | 'upstream_failure'
  | 'upstream_timeout'
  | 'unavailable'
  | 'hostkey_mismatch'
  | 'network_error'

export interface ApiErrorBody {
  code: ErrorCode
  message: string
  details?: Record<string, unknown>
  request_id?: string
}

export class ApiError extends Error {
  readonly status: number
  readonly code: ErrorCode
  readonly details: Record<string, unknown>
  readonly requestId: string

  constructor(status: number, body: ApiErrorBody) {
    super(body.message)
    this.name = 'ApiError'
    this.status = status
    this.code = body.code
    this.details = body.details ?? {}
    this.requestId = body.request_id ?? ''
  }

  /** Field-level messages from a 422, for rendering next to inputs. */
  get fields(): Record<string, string> {
    const raw = this.details.fields
    if (!raw || typeof raw !== 'object') return {}
    const out: Record<string, string> = {}
    for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
      out[key] = String(value)
    }
    return out
  }

  get isAuth(): boolean {
    return this.code === 'unauthenticated' || this.status === 401
  }

  get isNotImplemented(): boolean {
    return this.code === 'not_implemented'
  }

  /** The phase a not-yet-built feature is scheduled for, for Coming Soon copy. */
  get phase(): string {
    return typeof this.details.phase === 'string' ? this.details.phase : ''
  }
}

function readCookie(name: string): string {
  const prefix = `${name}=`
  for (const part of document.cookie.split('; ')) {
    if (part.startsWith(prefix)) return decodeURIComponent(part.slice(prefix.length))
  }
  return ''
}

function csrfToken(): string {
  // The __Host- prefixed name is used when served over HTTPS; try both so the
  // client works in a plain-HTTP development instance too.
  return readCookie(CSRF_COOKIE_SECURE) || readCookie(CSRF_COOKIE)
}

/** Called when the server reports the session is gone, so the shell can react. */
type UnauthorizedHandler = () => void
let onUnauthorized: UnauthorizedHandler | null = null

export function setUnauthorizedHandler(handler: UnauthorizedHandler | null): void {
  onUnauthorized = handler
}

interface RequestOptions {
  method?: string
  body?: unknown
  signal?: AbortSignal
  /** Confirmation token from a 412, replayed to authorise a destructive action. */
  confirm?: string
  /** Suppresses the global unauthorized handler, used by the login screen. */
  quiet?: boolean
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = options.method ?? 'GET'
  const headers: Record<string, string> = { Accept: 'application/json' }

  if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json'
  }
  if (method !== 'GET' && method !== 'HEAD') {
    headers[CSRF_HEADER] = csrfToken()
  }
  if (options.confirm) {
    headers['X-AXT-Confirm'] = options.confirm
  }

  let response: Response
  try {
    response = await fetch(path, {
      method,
      headers,
      // same-origin is enough because the SPA is served by the backend; it also
      // means no CORS preflight ever happens.
      credentials: 'same-origin',
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      signal: options.signal,
    })
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === 'AbortError') throw cause
    throw new ApiError(0, {
      code: 'network_error',
      message: 'Could not reach the server. Check your connection and try again.',
    })
  }

  if (response.status === 204) return undefined as T

  const text = await response.text()
  let payload: unknown = undefined
  if (text) {
    try {
      payload = JSON.parse(text)
    } catch {
      // A non-JSON body from an API path means something upstream replaced the
      // response -- a proxy error page, most often.
      if (!response.ok) {
        throw new ApiError(response.status, {
          code: 'internal_error',
          message: `Unexpected response from the server (HTTP ${response.status}).`,
        })
      }
    }
  }

  if (!response.ok) {
    const body = (payload as { error?: ApiErrorBody } | undefined)?.error
    const error = new ApiError(
      response.status,
      body ?? { code: 'internal_error', message: `HTTP ${response.status}` },
    )
    if (error.isAuth && !options.quiet) onUnauthorized?.()
    throw error
  }

  return payload as T
}

export const api = {
  get: <T>(path: string, signal?: AbortSignal) => request<T>(path, { signal }),
  post: <T>(path: string, body?: unknown, opts?: Omit<RequestOptions, 'method' | 'body'>) =>
    request<T>(path, { ...opts, method: 'POST', body }),
  patch: <T>(path: string, body?: unknown) => request<T>(path, { method: 'PATCH', body }),
  put: <T>(path: string, body?: unknown) => request<T>(path, { method: 'PUT', body }),
  del: <T>(path: string, opts?: Omit<RequestOptions, 'method'>) =>
    request<T>(path, { ...opts, method: 'DELETE' }),
}

/** Collections come back wrapped so a cursor can be added without a breaking change. */
export interface ListResponse<T> {
  items: T[]
  next_cursor?: string
  total?: number
}

export function items<T>(response: ListResponse<T> | undefined): T[] {
  return response?.items ?? []
}
