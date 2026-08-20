/** Formatting helpers. Kept in one place so units and relative times read the
 *  same everywhere in the UI. */

export function formatBytes(bytes: number | undefined | null): string {
  if (bytes === undefined || bytes === null) return '—'
  if (bytes < 1024) return `${bytes} B`
  const units = ['KiB', 'MiB', 'GiB', 'TiB']
  let value = bytes / 1024
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit += 1
  }
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`
}

export function formatSpeed(bytesPerSecond: number): string {
  if (bytesPerSecond <= 0) return '—'
  return `${formatBytes(bytesPerSecond)}/s`
}

/** Remaining time from a transfer's progress. Returns "—" when it cannot be known. */
export function formatETA(transferred: number, total: number | undefined, speed: number): string {
  if (!total || speed <= 0 || transferred >= total) return '—'
  const seconds = Math.round((total - transferred) / speed)
  return formatDuration(seconds)
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  if (hours < 24) return `${hours}h ${minutes}m`
  return `${Math.floor(hours / 24)}d ${hours % 24}h`
}

/**
 * Relative time, phrased the way a person would say it.
 *
 * "5 minutes ago" is more useful than a timestamp in a Recent list, where the
 * question is always "was that this session or last week".
 */
export function formatRelative(iso: string | undefined): string {
  if (!iso) return '—'
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return '—'

  const seconds = Math.round((Date.now() - then) / 1000)
  if (seconds < 10) return 'just now'
  if (seconds < 60) return `${seconds} seconds ago`

  const minutes = Math.round(seconds / 60)
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? '' : 's'} ago`

  const hours = Math.round(minutes / 60)
  if (hours < 24) return `${hours} hour${hours === 1 ? '' : 's'} ago`

  const days = Math.round(hours / 24)
  if (days === 1) return 'yesterday'
  if (days < 30) return `${days} days ago`

  return new Date(iso).toLocaleDateString()
}

export function formatTimestamp(iso: string | undefined): string {
  if (!iso) return '—'
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return '—'
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

/** Renders a POSIX mode as `rwxr-xr-x`, the form engineers read fluently. */
export function formatMode(mode: number): string {
  const bits = ['r', 'w', 'x']
  let out = ''
  for (let group = 2; group >= 0; group -= 1) {
    const value = (mode >> (group * 3)) & 0b111
    for (let bit = 0; bit < 3; bit += 1) {
      out += value & (0b100 >> bit) ? bits[bit] : '-'
    }
  }
  return out
}

/**
 * Fuzzy subsequence match with scoring.
 *
 * Weighted so a word-boundary hit beats a mid-word one, and a prefix beats both.
 * That is what makes "pw1" find "prod-web01" ahead of "power-switch-1".
 */
export function fuzzyScore(haystack: string, needle: string): number {
  if (!needle) return 1
  const target = haystack.toLowerCase()
  const query = needle.toLowerCase()

  if (target === query) return 1000
  if (target.startsWith(query)) return 500 + (100 - Math.min(100, target.length))

  let score = 0
  let targetIndex = 0
  let previousMatch = -1

  for (const char of query) {
    const found = target.indexOf(char, targetIndex)
    if (found === -1) return 0

    score += 10
    // Consecutive characters are a stronger signal than scattered ones.
    if (found === previousMatch + 1) score += 15
    // A match at a word boundary is what the user probably meant.
    if (found === 0 || '-_. /:'.includes(target[found - 1] ?? '')) score += 20

    previousMatch = found
    targetIndex = found + 1
  }

  // Shorter targets win among equal matches: "web01" over "web01-backup-old".
  return score + Math.max(0, 40 - target.length)
}

/** Sorts by fuzzy score, dropping non-matches. */
export function fuzzyFilter<T>(list: T[], query: string, key: (item: T) => string): T[] {
  if (!query) return list
  return list
    .map((item) => ({ item, score: fuzzyScore(key(item), query) }))
    .filter((entry) => entry.score > 0)
    .sort((a, b) => b.score - a.score)
    .map((entry) => entry.item)
}

export function pluralize(count: number, singular: string, plural?: string): string {
  return `${count} ${count === 1 ? singular : (plural ?? `${singular}s`)}`
}
