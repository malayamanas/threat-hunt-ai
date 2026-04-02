---
name: fsiem-cmdb
description: Query the FortiSIEM CMDB: look up devices, list inventory, or trigger discovery.
---
# Command: /fsiem-cmdb
# Usage: /fsiem-cmdb <query, IP, hostname, or subcommand>

## Description
Query and manage the FortiSIEM Configuration Management Database (CMDB).

## Usage Patterns

### Look up a single device
`/fsiem-cmdb 10.0.0.50`
`/fsiem-cmdb web-server-01`

Calls `fsiem_cmdb_get_device`, displays:
- IP, hostname, device type, vendor/model/OS
- Organization (SP mode)
- Interfaces, applications, credentials (masked)
- Recent incidents involving this device

### List devices by type or range
`/fsiem-cmdb list firewalls`
`/fsiem-cmdb list 192.168.1.0/24`

Calls `fsiem_cmdb_get_devices` with filters.

### Trigger discovery
`/fsiem-cmdb discover 192.168.5.0/24`

Calls `fsiem_cmdb_trigger_discovery`, then polls until complete and shows newly found devices.

### Set credentials
`/fsiem-cmdb set-creds 10.0.0.50 SSH admin`

Prompts for password securely, then calls `fsiem_cmdb_set_credentials`.

### Organization management (Service Provider)
`/fsiem-cmdb list orgs`
`/fsiem-cmdb add org ACME_Corp`

## Output Format
Device lookups display a card:
```
Device: web-server-01 (10.0.0.50)
  Type:    Windows Server
  OS:      Windows Server 2022
  Vendor:  VMware (virtual)
  Org:     ACME_Corp
  Status:  Managed ✓
  Last seen in events: 4 minutes ago
```
