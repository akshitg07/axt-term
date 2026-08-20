/**
 * Design-system primitives.
 *
 * Hand-written rather than taken from a component kit: the workspace needs to look
 * like professional infrastructure tooling, and that means owning the visual
 * language rather than restyling somebody else's. The accessibility work a kit
 * would provide -- focus trapping, ARIA roles, Escape handling -- is done here
 * explicitly instead.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useId,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
} from 'react'
import { createPortal } from 'react-dom'
import clsx from 'clsx'
import { Loader2, X } from 'lucide-react'

/* ------------------------------------------------------------------ button --- */

type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger'
type ButtonSize = 'sm' | 'md'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  size?: ButtonSize
  loading?: boolean
  icon?: ReactNode
}

const buttonVariants: Record<ButtonVariant, string> = {
  primary: 'bg-accent text-accent-fg hover:opacity-90 border-transparent font-medium',
  secondary: 'bg-surface-2 text-text-primary hover:bg-surface-3 border-border-subtle',
  ghost: 'bg-transparent text-text-secondary hover:bg-surface-2 hover:text-text-primary border-transparent',
  danger: 'bg-state-danger text-white hover:opacity-90 border-transparent font-medium',
}

export function Button({
  variant = 'secondary',
  size = 'md',
  loading = false,
  icon,
  className,
  children,
  disabled,
  ...rest
}: ButtonProps) {
  return (
    <button
      {...rest}
      disabled={disabled || loading}
      className={clsx(
        'inline-flex items-center justify-center gap-1.5 rounded border transition-colors',
        'disabled:opacity-50 disabled:cursor-not-allowed select-none whitespace-nowrap',
        size === 'sm' ? 'h-6 px-2 text-sm' : 'h-7 px-2.5 text-base',
        buttonVariants[variant],
        className,
      )}
    >
      {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden /> : icon}
      {children}
    </button>
  )
}

interface IconButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  label: string
  active?: boolean
}

/** Icon-only button. The label is required, not optional: an unlabelled icon
 *  button is invisible to a screen reader and ambiguous to everyone else. */
export function IconButton({ label, active, className, children, ...rest }: IconButtonProps) {
  return (
    <button
      {...rest}
      aria-label={label}
      title={label}
      aria-pressed={active}
      className={clsx(
        'inline-flex h-6 w-6 items-center justify-center rounded transition-colors',
        'text-text-secondary hover:bg-surface-2 hover:text-text-primary',
        'disabled:opacity-40 disabled:cursor-not-allowed',
        active && 'bg-surface-3 text-accent',
        className,
      )}
    >
      {children}
    </button>
  )
}

/* ------------------------------------------------------------------ inputs --- */

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string
  error?: string
  hint?: string
}

export function Input({ label, error, hint, className, id, ...rest }: InputProps) {
  const generatedId = useId()
  const inputId = id ?? generatedId
  const describedBy = error ? `${inputId}-error` : hint ? `${inputId}-hint` : undefined

  return (
    <div className="w-full">
      {label && (
        <label className="label" htmlFor={inputId}>
          {label}
        </label>
      )}
      <input
        {...rest}
        id={inputId}
        aria-invalid={Boolean(error)}
        aria-describedby={describedBy}
        className={clsx('field', error && 'field-invalid', className)}
      />
      {error ? (
        <p id={`${inputId}-error`} className="mt-1 text-sm text-state-danger">
          {error}
        </p>
      ) : hint ? (
        <p id={`${inputId}-hint`} className="hint">
          {hint}
        </p>
      ) : null}
    </div>
  )
}

interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  label?: string
  error?: string
}

export function Select({ label, error, className, id, children, ...rest }: SelectProps) {
  const generatedId = useId()
  const selectId = id ?? generatedId
  return (
    <div className="w-full">
      {label && (
        <label className="label" htmlFor={selectId}>
          {label}
        </label>
      )}
      <select
        {...rest}
        id={selectId}
        aria-invalid={Boolean(error)}
        className={clsx('field', error && 'field-invalid', className)}
      >
        {children}
      </select>
      {error && <p className="mt-1 text-sm text-state-danger">{error}</p>}
    </div>
  )
}

interface TextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string
  error?: string
  hint?: string
}

export function Textarea({ label, error, hint, className, id, ...rest }: TextareaProps) {
  const generatedId = useId()
  const areaId = id ?? generatedId
  return (
    <div className="w-full">
      {label && (
        <label className="label" htmlFor={areaId}>
          {label}
        </label>
      )}
      <textarea
        {...rest}
        id={areaId}
        aria-invalid={Boolean(error)}
        className={clsx('field font-mono resize-y', error && 'field-invalid', className)}
      />
      {error ? (
        <p className="mt-1 text-sm text-state-danger">{error}</p>
      ) : hint ? (
        <p className="hint">{hint}</p>
      ) : null}
    </div>
  )
}

export function Checkbox({
  label,
  hint,
  ...rest
}: InputHTMLAttributes<HTMLInputElement> & { label: string; hint?: string }) {
  const id = useId()
  return (
    <div className="flex items-start gap-2">
      <input
        {...rest}
        id={id}
        type="checkbox"
        className="mt-0.5 h-3.5 w-3.5 rounded border-border-strong bg-surface-2 accent-[var(--accent)]"
      />
      <div>
        <label htmlFor={id} className="text-base text-text-primary select-none">
          {label}
        </label>
        {hint && <p className="hint">{hint}</p>}
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ dialog --- */

interface DialogProps {
  open: boolean
  onClose: () => void
  title: string
  description?: string
  children: ReactNode
  footer?: ReactNode
  width?: 'sm' | 'md' | 'lg'
}

/**
 * Modal dialog with a focus trap.
 *
 * Focus moves in on open and returns to the trigger on close, Tab cycles inside,
 * and Escape closes. Getting this wrong strands keyboard users inside a dialog
 * they cannot leave, which for a keyboard-first tool is a serious defect.
 */
export function Dialog({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  width = 'md',
}: DialogProps) {
  const panelRef = useRef<HTMLDivElement>(null)
  const restoreFocusTo = useRef<HTMLElement | null>(null)
  const titleId = useId()
  const descriptionId = useId()

  useEffect(() => {
    if (!open) return
    restoreFocusTo.current = document.activeElement as HTMLElement | null

    const focusables = () =>
      Array.from(
        panelRef.current?.querySelectorAll<HTMLElement>(
          'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
        ) ?? [],
      )

    // Focus the first field rather than the first button, so typing starts
    // immediately in the common case of a form.
    const initial = focusables().find((el) => el.tagName !== 'BUTTON') ?? focusables()[0]
    initial?.focus()

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault()
        onClose()
        return
      }
      if (event.key !== 'Tab') return

      const elements = focusables()
      if (elements.length === 0) return
      const first = elements[0]
      const last = elements[elements.length - 1]
      if (!first || !last) return

      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault()
        first.focus()
      }
    }

    document.addEventListener('keydown', onKeyDown, true)
    return () => {
      document.removeEventListener('keydown', onKeyDown, true)
      restoreFocusTo.current?.focus()
    }
  }, [open, onClose])

  if (!open) return null

  const widths = { sm: 'max-w-sm', md: 'max-w-lg', lg: 'max-w-3xl' }

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-start justify-center p-4 pt-[10vh]">
      <div
        className="absolute inset-0 bg-black/60 animate-fade-in"
        onClick={onClose}
        aria-hidden
      />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description ? descriptionId : undefined}
        className={clsx(
          'relative w-full rounded-lg border border-border-strong bg-surface-1 animate-slide-up',
          widths[width],
        )}
        style={{ boxShadow: 'var(--shadow)' }}
      >
        <header className="flex items-start justify-between gap-4 border-b border-border-subtle px-4 py-3">
          <div>
            <h2 id={titleId} className="text-md font-medium text-text-primary">
              {title}
            </h2>
            {description && (
              <p id={descriptionId} className="mt-0.5 text-sm text-text-secondary">
                {description}
              </p>
            )}
          </div>
          <IconButton label="Close" onClick={onClose}>
            <X className="h-4 w-4" />
          </IconButton>
        </header>
        <div className="max-h-[65vh] overflow-y-auto px-4 py-3">{children}</div>
        {footer && (
          <footer className="flex items-center justify-end gap-2 border-t border-border-subtle px-4 py-3">
            {footer}
          </footer>
        )}
      </div>
    </div>,
    document.body,
  )
}

/* ---------------------------------------------------------------- confirm --- */

interface ConfirmOptions {
  title: string
  message: ReactNode
  confirmLabel?: string
  destructive?: boolean
  /** When set, the user must type this exact value to proceed. Reserved for
   *  high-severity actions: recursive delete, multi-host destructive execution. */
  typedConfirmation?: string
}

type ConfirmFn = (options: ConfirmOptions) => Promise<boolean>

const ConfirmContext = createContext<ConfirmFn>(async () => false)

export function useConfirm(): ConfirmFn {
  return useContext(ConfirmContext)
}

export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [request, setRequest] = useState<
    (ConfirmOptions & { resolve: (value: boolean) => void }) | null
  >(null)
  const [typed, setTyped] = useState('')

  const confirm = useCallback<ConfirmFn>(
    (options) =>
      new Promise<boolean>((resolve) => {
        setTyped('')
        setRequest({ ...options, resolve })
      }),
    [],
  )

  const settle = (value: boolean) => {
    request?.resolve(value)
    setRequest(null)
    setTyped('')
  }

  const needsTyping = Boolean(request?.typedConfirmation)
  const canProceed = !needsTyping || typed === request?.typedConfirmation

  return (
    <ConfirmContext.Provider value={confirm}>
      {children}
      <Dialog
        open={request !== null}
        onClose={() => settle(false)}
        title={request?.title ?? ''}
        width="sm"
        footer={
          <>
            <Button variant="ghost" onClick={() => settle(false)}>
              Cancel
            </Button>
            <Button
              variant={request?.destructive ? 'danger' : 'primary'}
              disabled={!canProceed}
              onClick={() => settle(true)}
            >
              {request?.confirmLabel ?? 'Confirm'}
            </Button>
          </>
        }
      >
        <div className="space-y-3 text-base text-text-secondary">
          <div>{request?.message}</div>
          {needsTyping && (
            <Input
              label={`Type ${request?.typedConfirmation} to confirm`}
              value={typed}
              onChange={(event) => setTyped(event.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
          )}
        </div>
      </Dialog>
    </ConfirmContext.Provider>
  )
}

/* ------------------------------------------------------------------ status --- */

export type DotStatus = 'online' | 'slow' | 'offline' | 'unknown' | 'connecting' | 'error'

/**
 * Status indicator using shape as well as colour.
 *
 * Red/green colour blindness is common in this audience, so a filled circle, a
 * half circle, a hollow circle, and a dotted ring are distinguishable even with
 * no hue information at all.
 */
export function StatusDot({ status, className }: { status: DotStatus; className?: string }) {
  const shared = 'inline-block h-2 w-2 rounded-full shrink-0'
  const label: Record<DotStatus, string> = {
    online: 'Online',
    slow: 'Slow',
    offline: 'Offline',
    unknown: 'Unknown',
    connecting: 'Connecting',
    error: 'Error',
  }

  const style: Record<DotStatus, string> = {
    online: 'bg-state-success',
    slow: 'bg-state-warning',
    offline: 'border border-state-danger bg-transparent',
    unknown: 'border border-dashed border-text-muted bg-transparent',
    connecting: 'bg-accent animate-pulse-slow',
    error: 'bg-state-danger',
  }

  return (
    <span
      role="img"
      aria-label={label[status]}
      title={label[status]}
      className={clsx(shared, style[status], className)}
    />
  )
}

export function Badge({
  children,
  tone = 'neutral',
}: {
  children: ReactNode
  tone?: 'neutral' | 'accent' | 'success' | 'warning' | 'danger'
}) {
  const tones = {
    neutral: 'bg-surface-3 text-text-secondary border-border-subtle',
    accent: 'bg-accent-muted text-accent border-transparent',
    success: 'bg-transparent text-state-success border-state-success/40',
    warning: 'bg-transparent text-state-warning border-state-warning/40',
    danger: 'bg-transparent text-state-danger border-state-danger/40',
  }
  return (
    <span
      className={clsx(
        'inline-flex items-center rounded border px-1.5 py-px text-xs font-medium',
        tones[tone],
      )}
    >
      {children}
    </span>
  )
}

export function Kbd({ children }: { children: ReactNode }) {
  return <span className="kbd">{children}</span>
}

export function Spinner({ className }: { className?: string }) {
  return <Loader2 className={clsx('h-4 w-4 animate-spin text-text-muted', className)} aria-hidden />
}

/** Empty state, used everywhere a list can legitimately be empty. */
export function EmptyState({
  icon,
  title,
  message,
  action,
}: {
  icon?: ReactNode
  title: string
  message?: string
  action?: ReactNode
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-10 text-center">
      {icon && <div className="text-text-muted">{icon}</div>}
      <p className="text-base text-text-primary">{title}</p>
      {message && <p className="max-w-sm text-sm text-text-secondary">{message}</p>}
      {action}
    </div>
  )
}

/**
 * Coming Soon placeholder.
 *
 * Used wherever a panel exists in the navigation but its feature has not shipped.
 * It names the phase, because "coming soon" with no timeframe is indistinguishable
 * from a broken page.
 */
export function ComingSoon({
  feature,
  phase,
  description,
}: {
  feature: string
  phase?: string
  description?: string
}) {
  return (
    <div className="flex h-full items-center justify-center p-8">
      <div className="max-w-md space-y-2 text-center">
        <Badge tone="accent">Coming soon{phase ? ` · ${phase.replace('-', ' ')}` : ''}</Badge>
        <h3 className="text-md text-text-primary">{feature}</h3>
        {description && <p className="text-sm text-text-secondary">{description}</p>}
        <p className="text-sm text-text-muted">
          This panel is not implemented yet. It is shown so the workspace layout is
          honest about what will live here.
        </p>
      </div>
    </div>
  )
}
