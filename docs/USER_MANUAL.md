# User Manual
## CyberGuard AI — End-User Guide

**Version:** 1.0  
**Date:** September 2026  
**Audience:** IT Administrators, Security Engineers

---

## Welcome to CyberGuard AI

CyberGuard AI is your always-on, on-device security monitor. It watches every process running on your servers, analyzes network activity, and alerts you — or automatically stops — anything that looks like a threat. All without sending your data anywhere.

This guide will walk you through using the dashboard to monitor your infrastructure, respond to threats, and stay in control.

---

## 1. Getting Started

### 1.1 Logging In

1. Open your web browser and navigate to your CyberGuard dashboard URL (e.g., `https://dashboard.yourcompany.com`)
2. Enter your username and password
3. If your account has MFA enabled, enter your 6-digit authenticator code
4. Click **Sign In**

> **Tip:** If you forget your password, contact your system administrator to reset it. There is no "forgot password" email for security reasons.

---

### 1.2 Understanding Your Dashboard

When you first log in, you'll see the main dashboard with four key areas:

```
┌─────────────────────────────────────────────────────────────────┐
│  [1] LEFT SIDEBAR     │  [2] KPI ROW                            │
│                       │  Devices | Alerts | Kills | Avg Score   │
│  Navigation links     │─────────────────────────────────────────│
│  to all sections      │  [3] DEVICE OVERVIEW    [4] ALERT FEED  │
│                       │  List of all your       Recent alerts   │
│  ─────────────────    │  monitored machines     sorted by       │
│  [5] USER PROFILE     │  with status dots       severity        │
└─────────────────────────────────────────────────────────────────┘
```

**Status Colors — these are critical to understand:**

| Color | Meaning | What to do |
|---|---|---|
| 🟢 **Green** | No threats detected | No action needed |
| 🟡 **Yellow** | Suspicious activity — investigate | Review the device's process list |
| 🔴 **Red** | Active critical threat | Act immediately |
| ⚫ **Grey** | Device offline / agent not responding | Check agent is running on that machine |

---

## 2. Monitoring Your Devices

### 2.1 Device List

Click **Devices** in the sidebar to see all your monitored machines.

Each device card shows:
- **Hostname** — the machine's name
- **IP Address** — its network address
- **Status dot** — green/yellow/red/grey
- **Last seen** — when the agent last reported
- **Active alerts** — count of open alerts by severity

### 2.2 Viewing a Device's Processes

1. Click on any device name to open its **Detail View**
2. You'll see a **real-time process table** that updates every 5 seconds

**Process Table Columns:**

| Column | Description |
|---|---|
| **PID** | Process ID — the unique number assigned by the OS |
| **Name** | Process name |
| **CPU%** | How much CPU this process is using right now |
| **RAM** | Memory consumed by this process |
| **Net I/O** | Network traffic — bytes sent/received |
| **Score** | AI threat score from 0.00 (safe) to 1.00 (malicious) |
| **Status** | SAFE, SUSPICIOUS, MALICIOUS, or WHITELISTED |

**Interpreting Threat Scores:**

| Score | Color | Meaning |
|---|---|---|
| 0.00 – 0.29 | 🟢 Green | Normal process — no concern |
| 0.30 – 0.69 | 🟡 Amber | Unusual behavior — worth investigating |
| 0.70 – 1.00 | 🔴 Red | High confidence threat — take action |

> **Note:** CyberGuard AI does not automatically kill processes unless you've enabled Autonomous Mode. You are always in control.

---

## 3. Responding to Alerts

### 3.1 The Alert Center

Click **Alerts** in the sidebar. Alerts are sorted by severity (CRITICAL first).

Each alert shows:
- **Severity badge** — CRITICAL, HIGH, MEDIUM, LOW, INFO
- **Device name** — which machine it came from
- **Alert title** — what was detected
- **Time** — when it was detected
- **Action buttons** — what you can do about it

### 3.2 Alert Types

| Alert Type | What It Means |
|---|---|
| **Malicious Process** | AI classified a process as a high-confidence threat |
| **Suspicious Process** | AI found unusual behavior worth reviewing |
| **C2 Beaconing** | A process is making regular connections to an external server (possible remote control) |
| **DNS Tunneling** | Unusual DNS query patterns that may be smuggling data |
| **Port Scanning** | Something is scanning your ports (possible attacker recon) |
| **Data Exfiltration** | Unusually large amounts of data leaving your server |
| **Resource Anomaly** | CPU, RAM, or network usage far above normal baseline |

### 3.3 Responding to a Process Alert

When you see a MALICIOUS or SUSPICIOUS process alert:

1. **Click the alert** to open the detail view
2. Read the **"Why Flagged"** section to understand what triggered the alert:
   - Specific reasons from the AI (e.g., "unsigned executable in /tmp")
   - Network connections made by the process
   - Resource usage compared to baseline
3. Choose an action:

   - **🔴 Kill Process** — Immediately terminate the process on the server
   - **⏸ Quarantine** — Suspend the process (freeze it) so it can't do further harm while you investigate
   - **✅ Whitelist** — Mark this process as trusted so it won't be flagged again
   - **Dismiss** — Acknowledge and close the alert without taking action

> **Before killing a process:** Make sure you understand what it is. Killing a legitimate production process (like a database or web server) will cause downtime. When in doubt, use Quarantine first to safely pause it while you investigate.

### 3.4 Killing a Process

1. Click **Kill Process** in the alert detail view (or click the **Kill** button in the process table)
2. A confirmation dialog will appear showing:
   - Process name and PID
   - Executable path
   - Threat score and classification reasons
3. Read the details carefully, then click **Confirm Kill**
4. The process will be terminated within 1–2 seconds
5. A success confirmation will appear, and the process will disappear from the process table

> **System-critical processes** (like the OS init process) are automatically protected and cannot be killed through CyberGuard AI, even accidentally.

### 3.5 Quarantining a Process

Quarantine suspends a process without killing it. Use this when you want to:
- Stop the damage temporarily while you investigate
- Preserve the process for forensic analysis
- Avoid service disruption from a potentially false positive

1. Click **Quarantine** in the alert detail
2. The process is paused (it still exists but cannot run)
3. You can **Release** it later (resume it) or **Kill** it after investigation

### 3.6 Whitelisting a Process

If CyberGuard AI is flagging a legitimate process:

1. Click **Whitelist** in the alert detail or process table
2. Choose the whitelist type:
   - **By Name** — Whitelist all processes with this name (less precise, easier)
   - **By File Hash** — Whitelist only this exact executable (more precise, recommended)
3. Add a description explaining why you're whitelisting it
4. Choose scope: **This Device** or **All Devices**
5. Click **Add to Whitelist**

---

## 4. Audit Log

The audit log is a complete, tamper-proof record of every action taken by CyberGuard AI and your administrators.

### Viewing the Audit Log

1. Click **Audit Log** in the sidebar
2. Use filters to narrow results:
   - **Date Range** — filter by time period
   - **Device** — filter by specific machine
   - **Action Type** — Kill, Whitelist, Settings Change, etc.
   - **Performed By** — filter by user or "system" (for autonomous actions)

### Exporting the Audit Log

1. Click **Export** in the Audit Log view
2. Choose format: **CSV** (for spreadsheets) or **JSON** (for programmatic processing)
3. Select date range
4. Click **Download**

---

## 5. Settings & Configuration

### 5.1 Scan Settings

In **Settings > Scan Configuration:**

| Setting | Default | Description |
|---|---|---|
| **Scan Interval** | 5 seconds | How often to check all processes |
| **Suspicious Threshold** | 0.30 | Minimum score to trigger a SUSPICIOUS alert |
| **Malicious Threshold** | 0.70 | Minimum score to trigger a MALICIOUS alert |

> **Raising the threshold** reduces alerts but may miss some threats.  
> **Lowering the threshold** catches more but increases false positives.

### 5.2 Autonomous Kill Mode

> ⚠️ **This is a powerful setting. Use with caution.**

When enabled, CyberGuard AI will automatically terminate processes classified as MALICIOUS without waiting for your confirmation. This is useful for organizations without 24/7 monitoring.

**To enable:**
1. Go to **Settings > Response Mode**
2. Toggle **Autonomous Kill Mode** to ON
3. Set the **Auto-Kill Threshold** (default: 0.85 — only kills processes with very high confidence)
4. Save settings

**To be safe:**
- Start with Supervised Mode (the default) and review alerts for a week first
- Never lower the Auto-Kill Threshold below 0.75
- Always keep email notifications enabled when Autonomous Mode is on

### 5.3 Alert Notifications

Go to **Settings > Notifications** to configure:

- **Email alerts** — enter one or more email addresses
- **Severity threshold** — only notify for alerts at or above selected severity
- **Browser push notifications** — enable in-browser alerts (requires browser permission)

### 5.4 Managing the Whitelist

Go to **Settings > Whitelist** to view and manage all whitelist rules.

You can:
- View all global and device-specific whitelist rules
- Delete rules that are no longer needed
- See who added each rule and when

---

## 6. Understanding the AI

### How does CyberGuard AI decide something is suspicious?

The AI model analyzes multiple signals from each process:

- **CPU and RAM usage** — Is this process using far more resources than expected?
- **Network activity** — Is it sending/receiving unusual amounts of data? Connecting to unusual IPs?
- **Process location** — Is the executable in an unusual directory like `/tmp`?
- **Digital signature** — Is the executable properly signed by a trusted publisher?
- **Behavior patterns** — Is its behavior consistent with known malware patterns (cryptomining, C2 beaconing)?

The AI combines all these signals to produce a threat score between 0.0 and 1.0.

### Will it ever get it wrong?

Yes — no security tool is perfect. Common false positive situations:
- **Development tools** running high CPU (code compilers, test runners)
- **Backup agents** with high disk/network usage during backup windows
- **New or unusual legitimate software** the model hasn't seen before

If CyberGuard AI frequently flags a legitimate tool, whitelist it to stop the alerts.

### What if a real threat has a low score?

The AI is one layer of defense. CyberGuard AI also uses **rule-based heuristics** that can flag threats independent of the AI score. You should also review the alerts section regularly, not just wait for CRITICAL alerts.

---

## 7. Common Tasks Quick Reference

| Task | Where |
|---|---|
| See all device health | Dashboard → Devices |
| View process list for a server | Devices → Click device name |
| Kill a suspicious process | Process table → Kill button OR Alert → Kill Process |
| View all open alerts | Alerts |
| Whitelist a process | Alert detail → Whitelist OR Process table → Whitelist |
| View kill history | Audit Log → filter by action_type: kill_process |
| Export audit log | Audit Log → Export |
| Change scan interval | Settings → Scan Configuration |
| Enable autonomous mode | Settings → Response Mode |
| Add alert email | Settings → Notifications |

---

## 8. Getting Help

- **Documentation:** Visit your internal documentation portal or see the docs folder
- **Support:** Contact your organization's IT administrator or open a support ticket
- **Logs:** Share the agent logs from `/var/log/cyberguard-agent.log` with support

---

*End of User Manual v1.0*
