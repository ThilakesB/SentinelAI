# API Documentation
## CyberGuard AI — REST & WebSocket API Reference

**Version:** 1.0  
**Base URL:** `https://{your-server}:8443/api/v1`  
**Authentication:** Bearer JWT Token (obtain via `/auth/login`)  
**Content-Type:** `application/json`

---

## 1. Authentication

### POST `/auth/login`

Authenticate a user and receive a JWT token.

**Request Body:**
```json
{
  "username": "admin",
  "password": "your-password",
  "totp_code": "123456"   // Required if MFA is enabled
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "expires_in": 28800,
  "user": {
    "id": "uuid-here",
    "username": "admin",
    "role": "super_admin"
  }
}
```

**Error Responses:**
- `401 Unauthorized` — Invalid credentials
- `403 Forbidden` — Account locked after too many attempts
- `422 Unprocessable Entity` — MFA code required but not provided

---

### POST `/auth/logout`

Invalidate the current session token.

**Headers:** `Authorization: Bearer {token}`

**Response (204 No Content)**

---

### POST `/auth/refresh`

Refresh an expiring JWT token.

**Headers:** `Authorization: Bearer {token}`

**Response (200 OK):**
```json
{
  "access_token": "new-token-here",
  "expires_in": 28800
}
```

---

## 2. Devices

### GET `/devices`

List all registered devices.

**Headers:** `Authorization: Bearer {token}`

**Query Parameters:**
| Param | Type | Description |
|---|---|---|
| `status` | string | Filter by: `active`, `inactive`, `disconnected` |
| `threat_level` | string | Filter by: `green`, `yellow`, `red` |
| `page` | int | Page number (default: 1) |
| `page_size` | int | Results per page (default: 20, max: 100) |

**Response (200 OK):**
```json
{
  "devices": [
    {
      "id": "device-uuid",
      "hostname": "prod-server-01",
      "ip_address": "192.168.1.100",
      "os_type": "linux",
      "os_version": "Ubuntu 22.04.3 LTS",
      "agent_version": "1.0.0",
      "status": "active",
      "threat_level": "yellow",
      "last_heartbeat": "2026-09-23T17:30:00Z",
      "alert_count": {
        "critical": 1,
        "high": 2,
        "medium": 5
      }
    }
  ],
  "total": 12,
  "page": 1,
  "page_size": 20
}
```

---

### GET `/devices/{device_id}`

Get detailed information about a specific device.

**Response (200 OK):**
```json
{
  "id": "device-uuid",
  "hostname": "prod-server-01",
  "ip_address": "192.168.1.100",
  "os_type": "linux",
  "os_version": "Ubuntu 22.04.3 LTS",
  "agent_version": "1.0.0",
  "status": "active",
  "threat_level": "yellow",
  "last_heartbeat": "2026-09-23T17:30:00Z",
  "created_at": "2026-09-01T10:00:00Z",
  "current_metrics": {
    "cpu_pct": 34.2,
    "ram_used_mb": 4096,
    "ram_total_mb": 16384,
    "net_sent_mbps": 2.1,
    "net_recv_mbps": 0.8
  }
}
```

---

### POST `/devices/register`

Register a new agent with the API server. Called automatically by the agent during installation.

**Request Body:**
```json
{
  "hostname": "new-server-01",
  "ip_address": "192.168.1.105",
  "os_type": "linux",
  "os_version": "Ubuntu 22.04",
  "agent_version": "1.0.0",
  "registration_token": "one-time-token-from-admin"
}
```

**Response (201 Created):**
```json
{
  "device_id": "new-device-uuid",
  "api_key": "agent-api-key-for-this-device"
}
```

---

### DELETE `/devices/{device_id}`

Remove a device from monitoring. Requires `super_admin` or `it_admin` role.

**Response (204 No Content)**

---

## 3. Processes

### GET `/devices/{device_id}/processes`

Get the latest process snapshot for a device.

**Query Parameters:**
| Param | Type | Description |
|---|---|---|
| `classification` | string | Filter: `SAFE`, `SUSPICIOUS`, `MALICIOUS`, `WHITELISTED` |
| `min_threat_score` | float | Minimum threat score (0.0–1.0) |
| `sort` | string | Sort by: `threat_score`, `cpu_pct`, `ram_mb` (default: `threat_score`) |
| `order` | string | `asc` or `desc` (default: `desc`) |

**Response (200 OK):**
```json
{
  "device_id": "device-uuid",
  "scan_timestamp": "2026-09-23T17:30:05Z",
  "processes": [
    {
      "pid": 4521,
      "name": "suspicious_tool",
      "parent_pid": 1,
      "cpu_pct": 87.4,
      "ram_mb": 2048.5,
      "net_sent_bps": 1048576,
      "net_recv_bps": 512,
      "open_ports_count": 3,
      "threat_score": 0.92,
      "classification": "MALICIOUS",
      "executable_path": "/tmp/.hidden/suspicious_tool",
      "is_signed": false,
      "classification_reasons": [
        "High CPU usage by unsigned process",
        "Process located in /tmp directory",
        "Unusual outbound network traffic"
      ]
    }
  ],
  "total": 247
}
```

---

### GET `/devices/{device_id}/processes/history`

Get historical process data for threat investigation.

**Query Parameters:**
| Param | Type | Description |
|---|---|---|
| `pid` | int | Filter by specific PID |
| `name` | string | Filter by process name |
| `start_time` | ISO 8601 | Start of time range |
| `end_time` | ISO 8601 | End of time range |

**Response (200 OK):**
```json
{
  "process_name": "suspicious_tool",
  "history": [
    {
      "timestamp": "2026-09-23T17:00:00Z",
      "cpu_pct": 12.1,
      "threat_score": 0.35
    },
    {
      "timestamp": "2026-09-23T17:15:00Z",
      "cpu_pct": 67.8,
      "threat_score": 0.72
    },
    {
      "timestamp": "2026-09-23T17:30:00Z",
      "cpu_pct": 87.4,
      "threat_score": 0.92
    }
  ]
}
```

---

## 4. Threat Actions

### POST `/devices/{device_id}/processes/{pid}/kill`

Kill a process on the specified device. Requires `security_analyst`, `it_admin`, or `super_admin` role.

**Request Body:**
```json
{
  "reason": "Confirmed malicious process — C2 beaconing detected",
  "force": true   // false = graceful termination first (SIGTERM), true = immediate SIGKILL
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "audit_log_id": "audit-entry-uuid",
  "message": "Kill command sent to agent. Process will be terminated within 1 second.",
  "timestamp": "2026-09-23T17:31:00Z"
}
```

**Error Responses:**
- `403 Forbidden` — Insufficient role
- `404 Not Found` — Device or PID not found
- `409 Conflict` — Process is protected (system-critical PID)

---

### POST `/devices/{device_id}/processes/{pid}/whitelist`

Add a process to the whitelist.

**Request Body:**
```json
{
  "rule_type": "process_name",   // or "exe_sha256" or "signature_issuer"
  "rule_value": "my_backup_agent",
  "description": "Internal backup agent — safe to whitelist",
  "scope": "device"              // or "global"
}
```

**Response (201 Created):**
```json
{
  "whitelist_rule_id": "rule-uuid",
  "message": "Whitelist rule created successfully."
}
```

---

### POST `/devices/{device_id}/processes/{pid}/quarantine`

Suspend (SIGSTOP) a process without killing it.

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Process suspended. Use /release to resume or /kill to terminate."
}
```

---

### POST `/devices/{device_id}/processes/{pid}/release`

Release a quarantined process (SIGCONT).

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Process resumed."
}
```

---

## 5. Alerts

### GET `/alerts`

List all alerts across all devices.

**Query Parameters:**
| Param | Type | Description |
|---|---|---|
| `severity` | string | `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `status` | string | `open`, `acknowledged`, `resolved`, `dismissed` |
| `device_id` | UUID | Filter to specific device |
| `alert_type` | string | e.g. `malicious_process`, `network_c2_beacon` |
| `start_time` | ISO 8601 | Date range start |
| `end_time` | ISO 8601 | Date range end |
| `page` | int | Page number |
| `page_size` | int | Max 100 |

**Response (200 OK):**
```json
{
  "alerts": [
    {
      "id": "alert-uuid",
      "device_id": "device-uuid",
      "hostname": "prod-server-01",
      "alert_type": "malicious_process",
      "severity": "CRITICAL",
      "title": "Malicious process detected: suspicious_tool",
      "description": "Process scored 0.92 (MALICIOUS). Unusual outbound traffic to known C2 IP.",
      "pid": 4521,
      "process_name": "suspicious_tool",
      "threat_score": 0.92,
      "status": "open",
      "created_at": "2026-09-23T17:30:05Z"
    }
  ],
  "total": 8,
  "page": 1,
  "page_size": 20
}
```

---

### PATCH `/alerts/{alert_id}`

Update alert status (acknowledge, resolve, dismiss).

**Request Body:**
```json
{
  "status": "acknowledged",
  "note": "Investigating — do not auto-resolve"
}
```

**Response (200 OK):**
```json
{
  "id": "alert-uuid",
  "status": "acknowledged",
  "acknowledged_by": "admin",
  "acknowledged_at": "2026-09-23T17:35:00Z"
}
```

---

## 6. Audit Log

### GET `/audit-log`

Retrieve audit log entries.

**Query Parameters:**
| Param | Type | Description |
|---|---|---|
| `device_id` | UUID | Filter by device |
| `action_type` | string | e.g. `kill_process`, `whitelist_add` |
| `performed_by` | UUID | Filter by user ID |
| `start_time` | ISO 8601 | Date range start |
| `end_time` | ISO 8601 | Date range end |
| `page` | int | Page number |

**Response (200 OK):**
```json
{
  "entries": [
    {
      "id": 1042,
      "device_id": "device-uuid",
      "hostname": "prod-server-01",
      "action_type": "kill_process",
      "pid": 4521,
      "process_name": "suspicious_tool",
      "exe_sha256": "abc123...",
      "threat_score": 0.92,
      "kill_mode": "supervised",
      "performed_by": "admin",
      "timestamp": "2026-09-23T17:31:00Z",
      "entry_hash": "sha256-of-this-entry"
    }
  ],
  "total": 142
}
```

---

### GET `/audit-log/export`

Export audit log as CSV or JSON.

**Query Parameters:**
| Param | Type | Description |
|---|---|---|
| `format` | string | `csv` or `json` |
| `start_time` | ISO 8601 | Required |
| `end_time` | ISO 8601 | Required |

**Response:** File download (CSV or JSON)

---

## 7. Whitelist

### GET `/whitelist`

List all whitelist rules.

**Response (200 OK):**
```json
{
  "rules": [
    {
      "id": "rule-uuid",
      "device_id": null,
      "scope": "global",
      "rule_type": "process_name",
      "rule_value": "postgres",
      "description": "PostgreSQL database process",
      "added_by": "admin",
      "added_at": "2026-09-10T09:00:00Z"
    }
  ]
}
```

---

### DELETE `/whitelist/{rule_id}`

Remove a whitelist rule.

**Response (204 No Content)**

---

## 8. Settings

### GET `/settings`

Get current system configuration (super_admin only).

**Response (200 OK):**
```json
{
  "scan_interval_seconds": 5,
  "suspicious_threshold": 0.3,
  "malicious_threshold": 0.7,
  "autonomous_kill_threshold": 0.85,
  "autonomous_kill_enabled": false,
  "alert_email_enabled": true,
  "alert_email_addresses": ["security@example.com"],
  "data_retention_days": 90
}
```

---

### PATCH `/settings`

Update system configuration.

**Request Body:** (any subset of settings fields)
```json
{
  "scan_interval_seconds": 10,
  "autonomous_kill_enabled": true
}
```

**Response (200 OK):** Updated settings object

---

## 9. WebSocket API

Connect to receive real-time events.

**Endpoint:** `wss://{your-server}:8443/ws`  
**Auth:** Pass JWT token as query param: `?token={jwt_token}`

### Event Types

#### `process_update`
Fired every scan cycle with updated process data for a device.

```json
{
  "event": "process_update",
  "device_id": "device-uuid",
  "timestamp": "2026-09-23T17:30:05Z",
  "processes": [...] // Same format as GET /devices/{id}/processes
}
```

#### `alert_created`
Fired when a new alert is generated.

```json
{
  "event": "alert_created",
  "alert": {
    "id": "alert-uuid",
    "severity": "CRITICAL",
    "title": "Malicious process detected",
    "device_id": "device-uuid",
    "hostname": "prod-server-01",
    "created_at": "2026-09-23T17:30:05Z"
  }
}
```

#### `kill_action`
Fired when a process kill is executed (supervised or autonomous).

```json
{
  "event": "kill_action",
  "device_id": "device-uuid",
  "pid": 4521,
  "process_name": "suspicious_tool",
  "kill_mode": "supervised",
  "performed_by": "admin",
  "timestamp": "2026-09-23T17:31:00Z"
}
```

#### `device_status_change`
Fired when a device connects, disconnects, or changes threat level.

```json
{
  "event": "device_status_change",
  "device_id": "device-uuid",
  "hostname": "prod-server-01",
  "old_status": "active",
  "new_status": "disconnected",
  "old_threat_level": "yellow",
  "new_threat_level": "yellow",
  "timestamp": "2026-09-23T17:32:00Z"
}
```

---

## 10. Error Codes

| HTTP Status | Code | Description |
|---|---|---|
| 400 | `validation_error` | Invalid request body or query parameters |
| 401 | `unauthorized` | Missing or invalid JWT token |
| 403 | `forbidden` | Insufficient role permissions |
| 404 | `not_found` | Resource does not exist |
| 409 | `conflict` | Action not allowed (e.g., kill on protected PID) |
| 429 | `rate_limited` | Too many requests (login rate limit) |
| 500 | `internal_error` | Server error |
| 503 | `agent_unavailable` | Agent is disconnected or not responding |

---

*End of API Documentation v1.0*
