# Test Cases Document
## CyberGuard AI — Individual Test Scenarios

**Version:** 1.0  
**Date:** September 2026  
**Format:** TC-[Module]-[Number]

---

## Module 1: Agent — Process Monitoring

### TC-PM-001: Basic Process Discovery

**Description:** Verify the agent discovers all running processes on the host OS.  
**Priority:** P0 — Critical  
**Test Type:** Functional

**Pre-conditions:**
- CyberGuard agent is installed and running
- Agent has root/admin privileges

**Steps:**
1. Start the CyberGuard agent on a Linux test machine
2. Run `ps aux` on the same machine to get actual process list
3. Query the agent's process list via API: `GET /devices/{id}/processes`
4. Compare the two lists

**Expected Result:**
- Agent's process list contains every PID returned by `ps aux`
- CPU%, RAM values match within ±5% tolerance
- No process is missing from agent's list

**Pass Criteria:** ≥ 99% of processes from `ps aux` are present in agent report

---

### TC-PM-002: AI Threat Scoring — Known Safe Process

**Description:** Verify that a known-safe system process receives a low threat score.  
**Priority:** P0  
**Test Type:** AI Validation

**Pre-conditions:** Agent running with ONNX model loaded

**Steps:**
1. Identify `sshd` (SSH daemon) running on the test machine
2. Note its PID
3. Query agent process list and find `sshd` entry
4. Record its threat score

**Expected Result:**
- `sshd` threat score ≤ 0.15 (classified as SAFE)
- Classification label is "SAFE"

---

### TC-PM-003: AI Threat Scoring — Simulated Cryptominer

**Description:** Verify that a simulated cryptominer process receives a high threat score.  
**Priority:** P0  
**Test Type:** AI Validation

**Pre-conditions:** Test malware simulator binary available (no actual malware used)

**Steps:**
1. Start the cryptominer simulator: consumes 85% CPU, makes high-frequency DNS queries
2. Wait one scan cycle (5 seconds)
3. Query agent process list for the simulator's PID
4. Record its threat score and classification

**Expected Result:**
- Threat score ≥ 0.70 (classified as MALICIOUS or SUSPICIOUS)
- Alert is generated and visible in alert API

---

### TC-PM-004: Scan Cycle Latency

**Description:** Verify that one full process scan cycle completes within 100ms.  
**Priority:** P1  
**Test Type:** Performance

**Steps:**
1. Set up test machine with 300 running processes
2. Enable agent performance logging
3. Run 100 scan cycles
4. Collect scan cycle duration from logs

**Expected Result:**
- Average scan duration < 100ms
- p99 scan duration < 200ms
- No scan cycle exceeds 500ms

---

### TC-PM-005: CPU Overhead Measurement

**Description:** Verify agent CPU overhead stays below 3%.  
**Priority:** P0  
**Test Type:** Performance

**Steps:**
1. Measure baseline CPU usage on a machine without the agent
2. Start the agent
3. Measure CPU usage for 30 minutes with 150 processes running
4. Calculate delta (agent overhead)

**Expected Result:**
- Average agent CPU delta < 3%
- Peak agent CPU delta < 10%

---

### TC-PM-006: RAM Usage Limit

**Description:** Verify agent RAM stays below 512MB.  
**Priority:** P0  
**Test Type:** Performance

**Steps:**
1. Start agent on a test machine
2. Monitor agent RAM usage with `ps -o rss` every 10 seconds for 1 hour
3. Simulate high-load scenario (500 processes, 10% malicious)

**Expected Result:**
- Agent RAM usage never exceeds 512MB
- No memory leak (RAM usage stable after 1 hour)

---

## Module 2: Agent — Process Kill

### TC-KILL-001: Supervised Kill — Admin Confirmation Flow

**Description:** Verify the supervised kill flow requires admin confirmation before terminating a process.  
**Priority:** P0  
**Test Type:** Integration

**Pre-conditions:** Agent in Supervised Mode (default), test process running

**Steps:**
1. Start a test process: `sleep 9999`
2. Note its PID
3. Simulate it being flagged as MALICIOUS (manually set score via test API)
4. Verify CRITICAL alert appears in dashboard
5. Click "Kill" button on the alert
6. Verify confirmation dialog appears with process details
7. Click "Confirm Kill"
8. Verify process is terminated (`kill -0 {PID}` returns "no such process")
9. Verify audit log entry created

**Expected Result:**
- Process is NOT killed until admin confirms
- After confirmation, process terminates within 1 second
- Audit log entry contains: PID, process name, score, mode=supervised, timestamp, user

---

### TC-KILL-002: Autonomous Kill Mode

**Description:** Verify autonomous kill mode terminates processes without human intervention.  
**Priority:** P0  
**Test Type:** Functional

**Pre-conditions:** Agent in Autonomous Mode, kill threshold = 0.85

**Steps:**
1. Enable Autonomous Kill Mode via settings API
2. Start a test process that the AI model will score > 0.85 (use simulation helper)
3. Wait one scan cycle
4. Check if process is still running
5. Check audit log

**Expected Result:**
- Process terminated automatically without human action
- Audit log entry: mode=autonomous, performed_by=system
- Dashboard shows CRITICAL alert with "Auto-killed" badge

---

### TC-KILL-003: Protected PID Rejection — PID 1

**Description:** Verify that PID 1 (init/systemd) can NEVER be killed.  
**Priority:** P0 — CRITICAL safety test  
**Test Type:** Security / Safety

**Steps:**
1. Attempt to kill PID 1 via API: `POST /devices/{id}/processes/1/kill`
2. Attempt to kill PID 1 via direct agent API key call
3. Simulate agent in Autonomous Mode receiving a malicious classification for PID 1

**Expected Result:**
- API returns `409 Conflict` with message "Protected system process — kill rejected"
- Autonomous mode does NOT kill PID 1 even if AI scores it as 1.0
- Audit log records the rejected kill attempt

---

### TC-KILL-004: Kill Action in Audit Log — Hash Chain Integrity

**Description:** Verify kill actions are recorded with correct hash chain.  
**Priority:** P0  
**Test Type:** Security

**Steps:**
1. Execute 5 kill actions in sequence
2. Query audit log via API
3. For each entry, verify: `entry_hash == SHA256(all_fields || prev_entry_hash)`
4. Attempt to modify entry 3 directly in database
5. Re-verify hash chain

**Expected Result:**
- All 5 entries have correct hash chain before modification
- After DB modification attempt, hash chain verification fails for entries 3, 4, 5
- Tamper detection is evident

---

### TC-KILL-005: Kill on Offline Agent

**Description:** Verify behavior when kill is requested but agent is offline.  
**Priority:** P1  
**Test Type:** Error Handling

**Steps:**
1. Disconnect the agent (stop the agent service)
2. Attempt kill action from dashboard
3. Wait for response

**Expected Result:**
- API returns `503 Service Unavailable` with message "Agent is not connected"
- Kill is NOT executed
- No audit log entry created (no action occurred)
- Dashboard shows agent-offline indicator

---

## Module 3: Network Log Analysis

### TC-NET-001: C2 Beaconing Detection

**Description:** Verify C2 beaconing is detected from syslog.  
**Priority:** P0  
**Test Type:** Functional

**Steps:**
1. Inject synthetic syslog entries simulating a process making connections to `185.220.101.34:4444` every 60 seconds for 5 consecutive minutes
2. Wait for agent's log parser to process the file
3. Query alerts API

**Expected Result:**
- Alert of type `network_c2_beacon` created with severity HIGH or CRITICAL
- Alert contains destination IP: `185.220.101.34`

---

### TC-NET-002: DNS Tunneling Detection

**Description:** Verify DNS tunneling is detected.  
**Priority:** P0  
**Test Type:** Functional

**Steps:**
1. Inject syslog entries with DNS queries longer than 50 characters at rate > 100/minute
2. Wait for log parse cycle
3. Check alerts

**Expected Result:**
- Alert of type `network_dns_tunnel` generated
- Alert includes query frequency and example query string

---

### TC-NET-003: Local IOC Database Check

**Description:** Verify the local IOC database correctly flags known-bad IPs.  
**Priority:** P1  
**Test Type:** Functional

**Steps:**
1. Query local IOC DB for a known malicious IP included in test dataset
2. Generate syslog entry with a connection to that IP
3. Wait for processing
4. Check alert

**Expected Result:**
- Alert generated with `ioc_matched` field showing the matching IOC entry
- Alert works without internet connection

---

## Module 4: Authentication & Authorization

### TC-AUTH-001: Valid Login

**Description:** Verify successful authentication.  
**Priority:** P0  
**Test Type:** Functional

**Steps:**
1. POST to `/auth/login` with valid username and password
2. Inspect response

**Expected Result:**
- 200 OK with JWT token in response
- Token validates on subsequent API calls

---

### TC-AUTH-002: Invalid Password — Rate Limiting

**Description:** Verify brute force protection.  
**Priority:** P0  
**Test Type:** Security

**Steps:**
1. POST to `/auth/login` with correct username and wrong password 5 times

**Expected Result:**
- First 5 attempts return 401 Unauthorized
- 6th attempt returns 403 Forbidden with message "Account temporarily locked"

---

### TC-AUTH-003: Role Enforcement — Viewer Cannot Kill

**Description:** Verify viewer role cannot execute kill actions.  
**Priority:** P0  
**Test Type:** Security

**Steps:**
1. Login as a user with role = `viewer`
2. Attempt `POST /devices/{id}/processes/{pid}/kill`

**Expected Result:**
- 403 Forbidden returned
- Process is NOT killed
- Attempt is logged in audit log with status "unauthorized"

---

### TC-AUTH-004: Expired Token Rejection

**Description:** Verify expired JWT tokens are rejected.  
**Priority:** P0  
**Test Type:** Security

**Steps:**
1. Login and get a JWT token
2. Manually expire the token (advance expiry claim by modifying in test env, or wait 8 hours)
3. Use expired token in API request

**Expected Result:**
- 401 Unauthorized returned
- Message: "Token expired"

---

### TC-AUTH-005: MFA — Valid TOTP Code

**Description:** Verify MFA login with correct TOTP code.  
**Priority:** P1  
**Test Type:** Functional

**Steps:**
1. Enable MFA for test user account
2. Generate valid TOTP code using test secret
3. POST to `/auth/login` with username, password, and totp_code

**Expected Result:**
- 200 OK with JWT token

---

### TC-AUTH-006: MFA — Invalid TOTP Code

**Description:** Verify MFA rejects invalid TOTP codes.  
**Priority:** P1  
**Test Type:** Security

**Steps:**
1. Enable MFA for test user account
2. POST to `/auth/login` with username, password, and wrong totp_code = "000000"

**Expected Result:**
- 401 Unauthorized returned
- Message: "Invalid MFA code"

---

## Module 5: Dashboard

### TC-DASH-001: Real-time Process Update

**Description:** Verify dashboard process table updates in real-time via WebSocket.  
**Priority:** P0  
**Test Type:** Integration

**Steps:**
1. Open dashboard in browser for a device
2. Start a new test process on the monitored machine
3. Wait 5 seconds (one scan cycle)
4. Observe dashboard process table

**Expected Result:**
- New process appears in table within 6 seconds without manual refresh
- Threat score badge is visible

---

### TC-DASH-002: Critical Alert Notification

**Description:** Verify browser push notification fires for CRITICAL alerts.  
**Priority:** P1  
**Test Type:** Functional

**Steps:**
1. Enable push notifications in browser and dashboard settings
2. Simulate a CRITICAL alert (score = 0.95)
3. Observe browser

**Expected Result:**
- Browser push notification appears within 2 seconds of alert creation
- Notification shows device name, process name, and threat score

---

### TC-DASH-003: Kill Button — End to End

**Description:** Verify complete kill flow from dashboard UI.  
**Priority:** P0  
**Test Type:** E2E

**Steps:**
1. Open dashboard in browser
2. Navigate to device with a flagged process
3. Click Kill button on a SUSPICIOUS process
4. Confirm in dialog
5. Verify badge changes to "KILLED" in process table
6. Navigate to Audit Log and verify entry

**Expected Result:**
- Process table shows updated status within 2 seconds
- Audit log entry exists with correct details

---

*End of Test Cases Document v1.0 — additional test cases added per feature as development progresses*
