import type { ITheme } from '@xterm/xterm'

/**
 * Terminal colour schemes.
 *
 * Chosen independently of the UI theme, because a dark terminal inside a light UI
 * is a legitimate and common preference -- and because a scheme that renders
 * `ls` colours legibly is a different problem from one that renders a form.
 */
export interface TerminalTheme {
  id: string
  label: string
  theme: ITheme
}

const axtDark: ITheme = {
  background: '#0b0d0f',
  foreground: '#e6edf3',
  cursor: '#22d3ee',
  cursorAccent: '#0b0d0f',
  selectionBackground: '#155e6b',
  selectionForeground: '#e6edf3',
  black: '#1e2328',
  red: '#f85149',
  green: '#3fb950',
  yellow: '#d29922',
  blue: '#58a6ff',
  magenta: '#bc8cff',
  cyan: '#39c5cf',
  white: '#b1bac4',
  brightBlack: '#6b7681',
  brightRed: '#ff7b72',
  brightGreen: '#56d364',
  brightYellow: '#e3b341',
  brightBlue: '#79c0ff',
  brightMagenta: '#d2a8ff',
  brightCyan: '#56d4dd',
  brightWhite: '#f0f6fc',
}

const axtLight: ITheme = {
  background: '#ffffff',
  foreground: '#1f2328',
  cursor: '#0b7285',
  cursorAccent: '#ffffff',
  selectionBackground: '#a5e8f2',
  selectionForeground: '#1f2328',
  black: '#24292f',
  red: '#cf222e',
  green: '#116329',
  yellow: '#4d2d00',
  blue: '#0969da',
  magenta: '#8250df',
  cyan: '#1b7c83',
  white: '#6e7781',
  brightBlack: '#57606a',
  brightRed: '#a40e26',
  brightGreen: '#1a7f37',
  brightYellow: '#633c01',
  brightBlue: '#218bff',
  brightMagenta: '#a475f9',
  brightCyan: '#3192aa',
  brightWhite: '#8c959f',
}

const midnight: ITheme = {
  ...axtDark,
  background: '#000000',
  cursor: '#2dd4bf',
  cursorAccent: '#000000',
  selectionBackground: '#115e59',
}

/** Maximum contrast, no reliance on hue to distinguish anything. */
const highContrast: ITheme = {
  background: '#000000',
  foreground: '#ffffff',
  cursor: '#00e5ff',
  cursorAccent: '#000000',
  selectionBackground: '#005f6b',
  selectionForeground: '#ffffff',
  black: '#000000',
  red: '#ff5252',
  green: '#00e676',
  yellow: '#ffd600',
  blue: '#40c4ff',
  magenta: '#ea80fc',
  cyan: '#18ffff',
  white: '#ffffff',
  brightBlack: '#9e9e9e',
  brightRed: '#ff8a80',
  brightGreen: '#69f0ae',
  brightYellow: '#ffff00',
  brightBlue: '#80d8ff',
  brightMagenta: '#f8bbd0',
  brightCyan: '#84ffff',
  brightWhite: '#ffffff',
}

/** A muted scheme for long sessions, where saturated colours become tiring. */
const slate: ITheme = {
  background: '#12161b',
  foreground: '#c9d4de',
  cursor: '#8ab4f8',
  cursorAccent: '#12161b',
  selectionBackground: '#2c3a47',
  selectionForeground: '#e6edf3',
  black: '#1c222a',
  red: '#e0707a',
  green: '#7fb37f',
  yellow: '#c9a86a',
  blue: '#7fa8d4',
  magenta: '#a88fc4',
  cyan: '#78b0b8',
  white: '#a8b3bd',
  brightBlack: '#5a6672',
  brightRed: '#eb8f97',
  brightGreen: '#9bc79b',
  brightYellow: '#dcc08c',
  brightBlue: '#a0c2e0',
  brightMagenta: '#c2aed6',
  brightCyan: '#9bc7ce',
  brightWhite: '#dce4ec',
}

export const terminalThemes: TerminalTheme[] = [
  { id: 'axt-dark', label: 'AXT Dark', theme: axtDark },
  { id: 'axt-light', label: 'AXT Light', theme: axtLight },
  { id: 'midnight', label: 'Midnight', theme: midnight },
  { id: 'slate', label: 'Slate', theme: slate },
  { id: 'contrast', label: 'High Contrast', theme: highContrast },
]

export function terminalThemeById(id: string): ITheme {
  return terminalThemes.find((t) => t.id === id)?.theme ?? axtDark
}
