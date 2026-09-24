# UI/UX Design Document
## CyberGuard AI — Interface Design Specifications

**Version:** 1.0  
**Date:** September 2026  
**Design System:** Custom dark-tech cybersecurity theme

---

## 1. Design Philosophy

CyberGuard AI's interface must communicate **control, precision, and trust** to security professionals. The design language draws from:

- **Terminal aesthetics** — monospace elements for data, high-information density
- **Military dashboard** — clear threat-level indicators, no visual noise when calm
- **Medical monitor** — real-time vital signs that are readable at a glance

### Design Principles

1. **Signal over noise** — Every element on screen must earn its place. No decorative clutter.
2. **Threat-first hierarchy** — Critical threats always dominate the visual hierarchy.
3. **Color as meaning** — Green = safe, Yellow = watch, Red = act now. These colors are never used decoratively.
4. **Speed of comprehension** — Admin should understand the security posture in < 3 seconds.
5. **Dark mode first** — Security dashboards live in server rooms and NOCs. Dark mode is not optional.

---

## 2. Design Tokens

### Color System

```css
/* Background Layers */
--color-bg-base:        #0a0c0f;   /* Page background */
--color-bg-surface:     #111318;   /* Card / panel background */
--color-bg-elevated:    #1a1e26;   /* Modal / popover */
--color-bg-border:      #2a2f3a;   /* Dividers and borders */

/* Threat Status Colors */
--color-safe:           #22c55e;   /* Green — SAFE / Normal */
--color-safe-bg:        #052e16;   /* Dark green background for safe zones */
--color-suspicious:     #f59e0b;   /* Amber — SUSPICIOUS / Watch */
--color-suspicious-bg:  #2d1f00;   /* Dark amber background */
--color-malicious:      #ef4444;   /* Red — MALICIOUS / Act now */
--color-malicious-bg:   #2d0707;   /* Dark red background for critical rows */
--color-critical-glow:  #ef444440; /* Subtle red glow for critical alerts */

/* Accent & Brand */
--color-accent:         #3b82f6;   /* Blue — interactive elements, links */
--color-accent-hover:   #60a5fa;   /* Lighter blue on hover */
--color-accent-muted:   #1d4ed8;   /* Darker blue for backgrounds */

/* Text */
--color-text-primary:   #f1f5f9;   /* Main text — near white */
--color-text-secondary: #94a3b8;   /* Labels, meta — slate 400 */
--color-text-tertiary:  #475569;   /* Disabled / placeholder — slate 600 */
--color-text-mono:      #7dd3fc;   /* Monospace terminal text — light blue */

/* Semantic */
--color-info:           #38bdf8;   /* Info badges */
--color-warning:        #fb923c;   /* Warning badges */
--color-success:        #4ade80;   /* Success states */
```

### Typography

```css
/* Font Families */
--font-display:  'Outfit', 'Inter', sans-serif;    /* Headlines and navigation */
--font-body:     'Inter', sans-serif;               /* Body text, labels */
--font-mono:     'JetBrains Mono', 'Fira Code', monospace;  /* PIDs, IPs, scores, code */

/* Font Sizes */
--text-xs:    11px;  /* Metadata, timestamps */
--text-sm:    13px;  /* Table data, labels */
--text-base:  14px;  /* Body text */
--text-md:    16px;  /* Section titles */
--text-lg:    20px;  /* Card headings */
--text-xl:    24px;  /* Page headings */
--text-2xl:   32px;  /* Dashboard KPI numbers */
--text-hero:  48px;  /* Landing page hero */

/* Font Weights */
--weight-normal:   400;
--weight-medium:   500;
--weight-semibold: 600;
--weight-bold:     700;
```

### Spacing & Layout

```css
/* Base unit: 4px */
--space-1:   4px;
--space-2:   8px;
--space-3:   12px;
--space-4:   16px;
--space-5:   20px;
--space-6:   24px;
--space-8:   32px;
--space-10:  40px;
--space-12:  48px;
--space-16:  64px;

/* Border Radius */
--radius-sm:   4px;    /* Input fields, small chips */
--radius-md:   8px;    /* Cards, panels */
--radius-lg:   12px;   /* Modals */
--radius-pill: 9999px; /* Badge indicators */

/* Shadows */
--shadow-card: 0 1px 3px rgba(0,0,0,0.4), 0 1px 2px rgba(0,0,0,0.6);
--shadow-alert: 0 0 20px rgba(239,68,68,0.2);  /* Red glow for critical */
--shadow-elevated: 0 4px 16px rgba(0,0,0,0.5);
```

---

## 3. Page Layouts

### 3.1 Main Dashboard Layout

```
┌─────────────────────────────────────────────────────────┐
│  SIDEBAR (240px)   │  MAIN CONTENT AREA                  │
│  ─────────────     │  ─────────────────────────────────  │
│  🛡️ CyberGuard    │  [TOPBAR: breadcrumb + user menu]   │
│                    │                                     │
│  ▸ Dashboard       │  [KPI ROW: 4 stat cards]            │
│  ▸ Devices         │  devices | alerts | kills | score   │
│  ▸ Alerts          │                                     │
│  ▸ Processes       │  ┌──────────────┐ ┌──────────────┐  │
│  ▸ Network         │  │ DEVICE LIST  │ │ ALERT FEED   │  │
│  ▸ Audit Log       │  │              │ │              │  │
│  ▸ Whitelist       │  │ • Server A 🟢│ │ ⚠️ CRITICAL  │  │
│  ▸ Settings        │  │ • Server B 🔴│ │ ⚠️ HIGH      │  │
│                    │  │ • Server C 🟡│ │ ℹ️ MEDIUM    │  │
│  ─────────────     │  └──────────────┘ └──────────────┘  │
│  [User Profile]    │                                     │
│  [v1.0.0]          │  [THREAT TIMELINE CHART]            │
└─────────────────────────────────────────────────────────┘
```

### 3.2 Device Detail Layout

```
┌─────────────────────────────────────────────────────────┐
│  SIDEBAR  │  ◀ Back  /  prod-server-01  [🔴 CRITICAL]   │
│           │  ─────────────────────────────────────────  │
│           │  [HOST INFO BAR: IP | OS | Agent | Uptime]  │
│           │                                             │
│           │  [RESOURCE METERS: CPU | RAM | NET | DISK]  │
│           │  (animated real-time gauges)                │
│           │                                             │
│           │  [PROCESS TABLE - Real Time]                │
│           │  PID | Name | CPU% | RAM | Score | Actions  │
│           │  ─────────────────────────────────────────  │
│           │  4521  suspicious_tool  87%  2GB  0.92 🔴   │
│           │  [Kill] [Whitelist] [Details]               │
│           │  1     systemd          0%   12MB 0.01 🟢   │
│           │  ...                                        │
│           │                                             │
│           │  [ACTIVE ALERTS for this device]            │
└───────────────────────────────────────────────────────┘
```

### 3.3 Alert Detail Modal

```
┌─────────────────────────────────────────────────────────┐
│  ┌───────────────────────────────────────────────────┐  │
│  │  ⚠️ CRITICAL ALERT                          ✕ close│  │
│  │  ─────────────────────────────────────────────── │  │
│  │  Malicious Process Detected                       │  │
│  │  prod-server-01 · 23 Sep 2026 · 17:30:05         │  │
│  │                                                   │  │
│  │  PROCESS DETAILS                                  │  │
│  │  PID:        4521                                 │  │
│  │  Name:       suspicious_tool                      │  │
│  │  Path:       /tmp/.hidden/suspicious_tool         │  │
│  │  SHA256:     abc123def456...                      │  │
│  │  CPU:        87.4%                                │  │
│  │  RAM:        2,048 MB                             │  │
│  │  Threat Score: ████████████ 0.92 MALICIOUS        │  │
│  │                                                   │  │
│  │  WHY FLAGGED                                      │  │
│  │  • Unsigned executable in /tmp directory          │  │
│  │  • CPU spike: 2% → 87% in 45 seconds             │  │
│  │  • Outbound to known C2 IP: 185.220.101.34        │  │
│  │  • DNS query frequency: 320/minute (baseline: 4)  │  │
│  │                                                   │  │
│  │  ACTIONS                                          │  │
│  │  [🔴 Kill Process] [⏸ Quarantine] [✅ Whitelist] │  │
│  │  [Dismiss Alert]                                  │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

---

## 4. Component Specifications

### 4.1 Threat Score Badge

```
Score 0.0–0.29 → Green  badge: "SAFE"       bg: #052e16, text: #22c55e
Score 0.3–0.69 → Amber  badge: "SUSPICIOUS" bg: #2d1f00, text: #f59e0b
Score 0.7–1.0  → Red    badge: "MALICIOUS"  bg: #2d0707, text: #ef4444
```

Badge also displays a progress bar filled to the score value with the corresponding color.

### 4.2 Device Status Indicator

Round dot, 8px diameter:
- 🟢 `#22c55e` — Active, no threats
- 🟡 `#f59e0b` — Active, suspicious alerts
- 🔴 `#ef4444` — Active, critical alerts (pulse animation, 2s cycle)
- ⚫ `#475569` — Disconnected / Offline

### 4.3 Kill Button

```
Normal state:
  background: #1e0707
  border: 1px solid #ef4444
  text: #ef4444
  font: semibold, 13px

Hover state:
  background: #ef4444
  text: #ffffff
  transition: 200ms ease

Active/Click:
  scale: 0.97
  transition: 80ms

Disabled (protected PID):
  opacity: 0.35
  cursor: not-allowed
```

### 4.4 Process Table Row

```
Normal (SAFE):
  background: transparent
  border-bottom: 1px solid #2a2f3a

SUSPICIOUS row:
  background: #2d1f0020  (subtle amber tint)
  border-left: 3px solid #f59e0b
  border-bottom: 1px solid #2a2f3a

MALICIOUS row:
  background: #2d070720  (subtle red tint)
  border-left: 3px solid #ef4444
  box-shadow: inset 0 0 20px #ef444408
  animation: pulse-border 2s ease-in-out infinite
```

### 4.5 KPI Stat Card

```
Layout:   80px height, padded 20px
Content:  Large number (32px, semibold) + label (12px, secondary)
Border:   1px solid --color-bg-border
Corner:   8px radius
BG:       --color-bg-surface

Active threat count card:
  Border-left: 3px solid --color-malicious
  Number color: --color-malicious
```

---

## 5. Micro-Animations

### Real-time Updates
- Process table rows slide in from left (0→1 opacity, x: -8px → 0) when new data arrives
- Duration: 200ms, ease-out

### Threat Score Changes
- Score bar animates to new value over 500ms
- Color transitions smoothly with the score change

### Alert Appearance
- New CRITICAL alerts slide down from top of alert feed
- Red glow pulse (0→20px box-shadow) for 2 seconds

### Device Status Dot
- RED status dot: CSS pulse animation expanding ring
- Expansion: 8px → 20px diameter, opacity 1→0, 2s loop

### Kill Confirmation Dialog
- Shake animation (x: -4px → +4px, 3 cycles) on hover of Kill button to warn user
- Dialog appears with scale 0.95→1 + opacity 0→1, 200ms spring

---

## 6. Responsive Breakpoints

| Breakpoint | Width | Layout Change |
|---|---|---|
| Desktop | ≥ 1280px | Full sidebar + main content |
| Laptop | 1024–1279px | Collapsed sidebar (icons only) |
| Tablet | 768–1023px | Hidden sidebar (hamburger menu) |
| Mobile | < 768px | Single column, alert-focused view |

Note: The dashboard is primarily designed for desktop/laptop use by IT administrators. Mobile is a read-only simplified view.

---

## 7. Accessibility

- All interactive elements have visible focus rings (2px solid #3b82f6, offset 2px)
- Color is never the only indicator — icons and text labels accompany all status colors
- Process table supports keyboard navigation (arrow keys to navigate rows, Enter to open detail)
- Minimum contrast ratio: 4.5:1 for all text (WCAG AA)
- Screen reader labels on all icon-only buttons
- Alert severity communicated via `aria-live="assertive"` for CRITICAL alerts

---

## 8. Error States

### Agent Disconnected Banner
```
Position: Top of main content area
Style: Full-width amber banner
Text: "⚠️ prod-server-01 is not reporting. Last seen 5 minutes ago."
Action: [Retry Connection] button
```

### No Data / Empty State
```
Center of content area
Icon: Shield with question mark (outlined, 48px)
Text: "No processes to show. This device appears to be offline or the agent is starting up."
Action: [Refresh] button
```

### Kill Failed
```
Inline toast (bottom-right)
Style: Red background
Text: "Failed to kill PID 4521: agent did not respond within 5 seconds. Try again or SSH to the host directly."
Duration: 8 seconds
```

---

*End of UI/UX Design Document v1.0*
