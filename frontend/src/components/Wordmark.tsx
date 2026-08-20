import clsx from 'clsx'

/**
 * The wordmark: AXT followed by a terminal cursor block.
 *
 * Drawn as SVG rather than set in a font so it renders identically everywhere and
 * needs no webfont to have loaded first.
 */
export function Wordmark({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 132 28"
      className={clsx('text-text-primary', className)}
      role="img"
      aria-label="AXT-Term"
    >
      <text
        x="0"
        y="21"
        fill="currentColor"
        fontFamily="Inter, system-ui, sans-serif"
        fontSize="20"
        fontWeight="600"
        letterSpacing="1.5"
      >
        AXT
      </text>
      {/* The cursor: solid rather than blinking. A logo that blinks forever is a
          distraction in a tool people keep open all day. */}
      <rect x="52" y="7" width="9" height="15" rx="1.5" fill="var(--accent)" />
      <text
        x="68"
        y="21"
        fill="var(--text-secondary)"
        fontFamily="Inter, system-ui, sans-serif"
        fontSize="20"
        fontWeight="300"
        letterSpacing="0.5"
      >
        Term
      </text>
    </svg>
  )
}
