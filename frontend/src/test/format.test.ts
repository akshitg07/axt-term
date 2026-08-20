import { describe, expect, it } from 'vitest'

import { formatBytes, formatETA, formatMode, fuzzyScore, fuzzyFilter } from '@/lib/format'

describe('formatBytes', () => {
  it('uses binary units and drops decimals once the number is large', () => {
    expect(formatBytes(0)).toBe('0 B')
    expect(formatBytes(999)).toBe('999 B')
    expect(formatBytes(1024)).toBe('1.0 KiB')
    expect(formatBytes(1536)).toBe('1.5 KiB')
    expect(formatBytes(1024 * 1024 * 145)).toBe('145 MiB')
  })

  it('renders an unknown size as a dash rather than zero', () => {
    // Showing "0 B" for an unknown size makes a running transfer look finished.
    expect(formatBytes(undefined)).toBe('—')
    expect(formatBytes(null)).toBe('—')
  })
})

describe('formatETA', () => {
  it('reports remaining time from progress and speed', () => {
    expect(formatETA(50, 150, 10)).toBe('10s')
    expect(formatETA(0, 6000, 10)).toBe('10m 0s')
  })

  it('refuses to guess when it cannot know', () => {
    expect(formatETA(50, undefined, 10)).toBe('—')
    expect(formatETA(50, 150, 0)).toBe('—')
    expect(formatETA(150, 150, 10)).toBe('—')
  })
})

describe('formatMode', () => {
  it('renders octal modes the way engineers read them', () => {
    expect(formatMode(0o644)).toBe('rw-r--r--')
    expect(formatMode(0o755)).toBe('rwxr-xr-x')
    expect(formatMode(0o600)).toBe('rw-------')
    expect(formatMode(0o777)).toBe('rwxrwxrwx')
  })
})

describe('fuzzyScore', () => {
  it('ranks an exact match above a prefix above a subsequence', () => {
    const exact = fuzzyScore('web01', 'web01')
    const prefix = fuzzyScore('web01-backup', 'web01')
    const scattered = fuzzyScore('w-e-b-0-1', 'web01')
    expect(exact).toBeGreaterThan(prefix)
    expect(prefix).toBeGreaterThan(scattered)
  })

  it('returns zero when a character is missing', () => {
    expect(fuzzyScore('prod-web01', 'xyz')).toBe(0)
  })

  it('prefers word-boundary matches, so pw1 finds prod-web01 first', () => {
    const hosts = ['power-switch-1', 'prod-web01']
    const ranked = fuzzyFilter(hosts, 'pw1', (h) => h)
    expect(ranked[0]).toBe('prod-web01')
  })

  it('treats an empty query as matching everything, in original order', () => {
    const hosts = ['b', 'a']
    expect(fuzzyFilter(hosts, '', (h) => h)).toEqual(['b', 'a'])
  })
})
