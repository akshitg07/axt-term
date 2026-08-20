# 7. UI/UX Architecture

## 7.1 It is a workspace, not a dashboard

The mental model is a desk, not a report. There is one persistent surface; hosts and panels
come and go inside it. Nothing navigates *away* from the terminal — every feature is a
panel that appears beside or below it.

Concretely this rules out: a landing page with statistics cards, a left-nav of top-level
sections that swap the whole content area, and modal-heavy flows. It rules in: tabs, splits,
docked panels, a command palette, and an inspector.

## 7.2 Shell layout

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│ ▚ AXT-Term   ⌕ Search hosts, files, commands…              ⌘K   + New ▾   ◐  ⚙  ⏻  │ 40px
├────────────────┬─────────────────────────────────────────────────────────────────────┤
│ CONNECTIONS  ⌕ │ ● prod-web01 ⋮│ ○ prod-db01 │ ▣ WIN01 │ ⎈ k8s-prod │  +      ⤢  ⋮ │ 34px
│                ├─────────────────────────────────────────────────────────────────────┤
│ ⭐ Favorites  3│                                                                     │
│                │  akshit@prod-web01:~$ systemctl status nginx                        │
│ ▾ 📁 Production│  ● nginx.service - A high performance web server                     │
│   ▾ 📁 Web     │       Loaded: loaded (/lib/systemd/system/nginx.service; enabled)   │
│     ● web01    │       Active: active (running) since Mon 2026-08-17 03:11:04 UTC    │
│     ● web02    │                                                                     │
│     ○ web03    │  akshit@prod-web01:~$ ▊                                             │
│   ▸ 📁 Database│                                                                     │
│   ▸ 📁 Monitor │                                                                     │
│ ▸ 📁 Homelab   ├─────────────────────────────────────────────────────────────────────┤
│ ▸ 📁 Network   │ Terminal │ Files │ Editor │ Processes │ Services │ Logs │ System  ⌄ │ 30px
│                ├─────────────────────────────────────────────────────────────────────┤
│ ─────────────  │ ▸ Transfers (2 active)      ▸ Command Center      ▸ Tunnels        │
│ 📜 Snippets    │                                                                     │
│ 🔑 Credentials │   backup.tar.gz  ████████████████░░░░  82%  120/145 MB  11 MB/s 8s │ 25%
│ 🕘 Recent      │   config.yaml    ✓ completed                                        │
│ 🔀 Tunnels     │                                                                     │
├────────────────┴─────────────────────────────────────────────────────────────────────┤
│ ● prod-web01  ssh  ↑2.1 MB ↓840 KB  12ms │ 4 sessions │ REC │ ⚠ broadcast off │ ✓ ok │ 24px
└──────────────────────────────────────────────────────────────────────────────────────┘
   240px, resizable, collapsible (⌘B)
```

Five regions, each with one job:

| Region | Job | Collapsible |
| --- | --- | --- |
| Top bar | Global search, new-connection, theme, settings | No |
| Sidebar | Inventory navigation and secondary libraries | Yes (`Ctrl+B`) |
| Tab strip | Session switching, protocol/state at a glance | No |
| Session area | The work. Terminal, RDP canvas, file panes, editor | No |
| Context tabs | Per-host panels for the active session's host | — |
| Drawer | Cross-host activity: transfers, command jobs, tunnels | Yes (`Ctrl+J`) |
| Status bar | Live truth about the focused session | No |

The drawer is deliberately separate from the context tabs. Context tabs are *about this
host*; the drawer is *about everything I have running*. Conflating them is why file
transfers get lost in other tools.

## 7.3 Sidebar

A single virtualised tree with sections, not a nav menu. Filter-as-you-type collapses the
tree to matches with their ancestors, and `Enter` connects to the top match.

Each host row shows: health dot, name, protocol glyph, and — on hover — inline actions for
Terminal, Files, and an overflow menu with the full contextual set. A middle-click opens a
new tab, and `Shift`-click adds to a multi-select for the Command Center. Colour tags render
as a 2px left border rather than a filled chip, so a wall of hosts stays scannable.

Health dots are `● online`, `◐ slow`, `○ offline`, `◌ unknown`, distinguished by **shape as
well as colour** — colour alone fails for red/green colour blindness, which is common in
this audience.

Drag and drop moves hosts between folders and reorders them. The tree state (expanded nodes,
scroll position, width) persists per user.

## 7.4 Tabs

A tab is a *session*, not a page. It shows a state dot, the host name, and a protocol glyph
(`>_` SSH, `▣` RDP, `⇅` SFTP, `⎈` Kubernetes, `◧` Docker).

Supported: reorder by drag, close (`Ctrl+W`), duplicate (opens a second session to the same
host), pin (pinned tabs shrink to a glyph and sit left of unpinned ones), reconnect,
split, rename, and "close others / close to the right". Overflow becomes a searchable
dropdown rather than a scroll strip once tabs exceed the width — with 20 sessions open,
scrolling to find one is worse than typing two letters.

State dot semantics are strict, because ambiguity here costs real mistakes:

| Dot | Meaning |
| --- | --- |
| `●` solid | Connected and attached |
| `◐` pulsing | Connecting or reconnecting |
| `○` hollow | Session alive on the backend, no browser attachment |
| `⊘` | Disconnected; content is frozen history, input disabled |
| `!` | Failed, with the reason on hover |

`⊘` matters: a frozen terminal that still accepts keystrokes is how people believe they
restarted a service when they did not. Input is disabled and the pane shows a
`Reconnect` affordance.

## 7.5 Splits

A recursive binary tree of panes per tab. `Ctrl+Shift+D` splits right, `Ctrl+Shift+E`
splits down, `Ctrl+Shift+Z` maximises the focused pane temporarily (a zoom, not a layout
change — the layout returns on toggle). Dividers are 4px hit-targets with 1px visuals,
draggable, double-click to equalise. Each pane keeps its own session and its own status
line; the focused pane owns the status bar and the context tabs.

Panes can hold anything a tab can hold, so a terminal beside a file browser beside a log
tail is one layout, not three windows.

## 7.6 Command palette

`Ctrl+Shift+P` for commands, `Ctrl+K` for the object-first variant — the distinction
matters in practice: usually you know the *host* first, occasionally the *verb*.

Scored fuzzy matching (subsequence match, weighted for word-boundary hits, recency, and
frequency) over one flat result list grouped by kind:

```
┌────────────────────────────────────────────────────────────┐
│ ⌕ prod-web                                                 │
├────────────────────────────────────────────────────────────┤
│ HOSTS                                                      │
│ ● prod-web01      ssh   10.0.4.11    Production/Web    ⏎  │
│ ● prod-web02      ssh   10.0.4.12    Production/Web       │
│ ACTIONS ON prod-web01                                      │
│ ⇅ Open Files                                    ⌃⇧E       │
│ ⚙ Services                                                 │
│ SNIPPETS                                                   │
│ 📜 Nginx: test config and reload                           │
│ WORKSPACES                                                 │
│ ▤ Production Workspace                                     │
└────────────────────────────────────────────────────────────┘
```

Palette actions are the *same* registry the keyboard shortcuts and context menus bind to —
one command table, three surfaces. A feature that is not in the command registry is
unreachable by keyboard, which is treated as a bug.

## 7.7 Files

Two modes on one component. Single-pane remote browsing (default) and dual-pane
local↔remote (`Ctrl+Shift+2`).

```
┌─ LOCAL ─────────────────────────────┬─ REMOTE  prod-web01 ─────────────────────────┐
│ ⌂ / Downloads / release        ⟳ ⌕ │ ⌂ / opt / application              ⟳ ⌕ ⋮   │
├─────────────────────────────────────┼──────────────────────────────────────────────┤
│ Name          Size    Modified      │ Name        Size   Mode  Owner  Modified     │
│ ▸ ..                                │ ▸ ..                                         │
│ 📁 static     —       10:02         │ 📁 static   —      755   root   Aug 12 09:41 │
│ 📄 Dockerfile 1.2 KB  10:04         │ 📄 Dockerfile 1.1KB 644   root   Aug 09 14:22│
│ 📄 app.py     18 KB   10:04         │ 📄 app.py   17 KB  644   app    Aug 09 14:22 │
│ 📄 config.yaml 842 B  10:05         │ 📄 config.yaml 810B 640   app    Aug 11 08:03│
├─────────────────────────────────────┴──────────────────────────────────────────────┤
│              ← Download (F5)      Upload → (F6)      Edit (F4)   Delete (F8)       │
└────────────────────────────────────────────────────────────────────────────────────┘
```

Deliberate borrowings from the orthodox-file-manager tradition that WinSCP and its
predecessors got right: function keys for the primary verbs, `..` as a real row, focus
following the pane, typing to jump, and a status line that reports selection size. What we
improve: differences between panes are highlighted (same name, different size or mtime),
the transfer queue is a first-class drawer rather than a modal, and the editor opens in the
same workspace instead of spawning an external program.

Both panes are virtualised. Selection supports click, `Shift`-click ranges, `Ctrl`-click
toggles, `Ctrl+A`, and glob selection (`*.log`). Drag and drop works pane-to-pane and from
the desktop.

Every destructive action names its target in the confirmation, including the host —
"Delete 14 items from **prod-web01**:/var/log" reads differently from "Are you sure?", and
that difference prevents incidents.

## 7.8 Editor

Monaco in the session area, opened from the file list or `F4`. Tab title carries the file
name and host; a dirty dot marks unsaved changes; `Ctrl+S` saves via atomic write.

Language is detected from extension and from shebang/content for extensionless files
(`nginx.conf`, `Dockerfile`, systemd units, `.env`). A pre-save backup toggle defaults to
**on** for paths matching known-sensitive patterns (`/etc/**`, `**/nginx/**`, `**/*.service`)
and off elsewhere. If the remote mtime changed since load, saving raises a conflict dialog
with a diff rather than overwriting.

## 7.9 Command Center

```
┌────────────────────────────────────────────────────────────────────────────────────┐
│ COMMAND CENTER                              Targets: 5 hosts ▾   Mode: Parallel ▾  │
├────────────────────────────────────────────────────────────────────────────────────┤
│ $ df -h /                                                              ▶ Run  ⌘⏎  │
│   Concurrency 8   Timeout 60s   ☐ Stop on first error                              │
├────────────────────────────────────────────────────────────────────────────────────┤
│ ⌕ filter output            [All 5] [✓ 4] [✗ 1]              ⤓ Export ▾   ⟳ Retry ✗ │
├────────────────────────────────────────────────────────────────────────────────────┤
│ ▾ ● prod-web01   ✓ exit 0   0.4s                                                   │
│     Filesystem  Size  Used Avail Use% Mounted on                                   │
│     /dev/sda1   118G   71G   41G  64% /                                            │
│ ▸ ● prod-web02   ✓ exit 0   0.4s        /dev/sda1  118G  69G  43G  62% /           │
│ ▸ ● prod-db01    ✓ exit 0   0.6s        /dev/sda1  462G 388G  51G  89% /   ⚠       │
│ ▾ ○ prod-db02    ✗ dial tcp 10.0.4.22:22: i/o timeout                        ⟳     │
└────────────────────────────────────────────────────────────────────────────────────┘
```

Collapsed rows show a one-line summary so twenty hosts fit on screen; expanding shows full
output. Identical outputs group automatically ("12 hosts returned identical output"), which
is what makes scanning fifty results tractable. Failures sort to the top by default.

## 7.10 Broadcast mode

Broadcast is the most dangerous feature in the product, so its UI is intentionally loud and
slightly inconvenient.

Enabling requires a dialog listing every target host by name and typing the word
`BROADCAST`. While active:

- A persistent amber bar spans the top of the session area: `⚠ BROADCASTING TO 4 HOSTS —
  prod-web01, prod-web02, prod-web03, prod-web04 · Disable (⌃⇧B)`.
- Every participating pane gets a 2px amber border.
- The status bar turns amber.
- The favicon changes, so a background tab is identifiable.
- It disables automatically when a target disconnects, when the tab loses focus for more
  than 5 minutes, or on page reload — it is never restored silently by session persistence.

## 7.11 Keyboard model

Every command lives in a registry with an id, a label, a scope, and a default binding.
Settings shows the full table and allows rebinding with conflict detection. Terminal-focus
scope is respected: `Ctrl+W` closing a tab must not shadow the shell's word-erase, so
terminal-scoped panes pass through terminal control keys and app shortcuts use a
`Ctrl+Shift` prefix by default.

| Binding | Command |
| --- | --- |
| `Ctrl+K` | Quick connect (host-first search) |
| `Ctrl+Shift+P` | Command palette |
| `Ctrl+Shift+F` | Global search |
| `Ctrl+T` / `Ctrl+W` | New session / close session |
| `Ctrl+Tab` / `Ctrl+Shift+Tab` | Next / previous tab |
| `Alt+1…9` | Jump to tab N |
| `Ctrl+Shift+D` / `Ctrl+Shift+E` | Split right / split down |
| `Alt+←↑→↓` | Focus pane by direction |
| `Ctrl+Shift+Z` | Zoom focused pane |
| `Ctrl+B` / `Ctrl+J` | Toggle sidebar / drawer |
| `Ctrl+Shift+E` | Files panel for the active host |
| `Ctrl+Shift+S` | Snippets |
| `Ctrl+Shift+B` | Toggle broadcast (confirmation still required) |
| `Ctrl+Shift+C` / `Ctrl+Shift+V` | Copy / paste in terminal |
| `Ctrl+Shift+K` | Clear terminal |
| `Ctrl+F` | Search in terminal |
| `F4` / `F5` / `F6` / `F8` | Edit / download / upload / delete (files) |

## 7.12 Visual language

**Typography.** UI text in Inter (bundled, not from a CDN), 13px base with a 12px dense
variant for tables. Terminal and code in JetBrains Mono, 14px default. Both licensed for
redistribution and shipped with the application so the UI renders identically offline.

**Colour** is defined as semantic tokens over a neutral scale, never raw hex in components:

```
--surface-0   application background       --text-primary
--surface-1   panels                       --text-secondary
--surface-2   raised: tabs, inputs         --text-muted
--surface-3   overlays: palette, dialogs   --accent        (cyan — links, focus, active tab)
--border-subtle / --border-strong          --success / --warning / --danger / --info
```

Four themes ship: **Dark** (default), **Light**, **Midnight** (near-black OLED), and
**High Contrast** (WCAG AAA, thicker borders, no reliance on hue). Terminal themes are
chosen independently of the UI theme, because a dark terminal in a light UI is a legitimate
and common preference.

**Density.** 28px rows in trees and tables, 34px tabs, 8px base spacing unit. This is a
tool used for hours; wasted vertical space costs visible rows of `ps` output.

**Motion.** 120–160 ms ease-out on panel and overlay transitions; nothing animates in the
terminal viewport, and `prefers-reduced-motion` disables all of it. Animation must never
delay a keystroke rendering.

**Icons.** Lucide at 16px, 1.5px stroke, monochrome and inheriting text colour, with
protocol glyphs drawn as small custom marks so SSH/RDP/SFTP read distinctly at tab size.

## 7.13 Branding

Wordmark: `AXT` in a geometric sans with a terminal-cursor block after the `T` that blinks
once on load and then rests solid. Mark for favicon and small sizes: an `A` whose crossbar
extends right into a `>` chevron, with an underscore-cursor beneath — legible at 16px, which
most logos are not. Palette: near-black surfaces with a single cyan accent. Technical,
quiet, no gradients, no glow.

## 7.14 Responsive behaviour

| Width | Behaviour |
| --- | --- |
| ≥1280px | Full layout as drawn |
| 1024–1280px | Sidebar auto-collapses to icons; drawer becomes overlay |
| 768–1024px (tablet) | Sidebar as overlay; context tabs scroll; splits limited to two panes |
| <768px (mobile) | **Emergency administration mode** |

Mobile is scoped honestly: host list, single terminal, log viewer, service restart, basic
file browse and download, and RDP view. Splits, dual-pane files, the editor, and the
Command Center are hidden rather than crammed in. The terminal gains a control-key toolbar
(`Esc Tab Ctrl Alt ↑↓←→ | ~ /`) because a phone keyboard cannot send `Ctrl+C`. It is for the
2 a.m. page from a train, and it says so.

## 7.15 Notifications

Toasts, bottom-right, auto-dismissing after 6 s except errors, which persist until
dismissed. Coalesced by category — five completed transfers produce "5 transfers completed",
not five toasts. Anything with a location gets a click-through to it. Connection *state*
lives in the tab and status bar rather than in toasts, so a flapping link does not produce a
stream of popups. A count badge on the drawer replaces repeat notifications for ongoing
activity.

## 7.16 Accessibility

Full keyboard reachability is already required by the keyboard-first goal, and the rest
follows: visible focus rings (2px accent, never removed), Radix primitives for correct focus
trapping and ARIA in dialogs and menus, live regions for connection state and transfer
completion, AA contrast minimum in all themes and AAA in High Contrast, shape-plus-colour
status encoding, and honest labels on icon-only buttons. The terminal itself exposes
xterm.js's screen-reader mode as a setting, off by default because it costs performance.
