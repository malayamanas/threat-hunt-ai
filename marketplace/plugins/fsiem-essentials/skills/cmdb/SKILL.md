---
name: fsiem-cmdb
description: Query and manage the FortiSIEM CMDB — devices, credentials, discovery, and organizations. Use when working with device inventory or asset data.
---

# FortiSIEM CMDB Operations

The CMDB stores all managed device information. APIs use XML and live under `/phoenix/rest/cmdbDeviceInfo/`.

## Key Functions

- `fsiem_cmdb_get_devices(ip_range, device_type, org)` — list devices with filters
- `fsiem_cmdb_get_device(ip, hostname)` — full detail for one device
- `fsiem_cmdb_get_device_apps(ip)` — application inventory
- `fsiem_cmdb_set_credentials(ip, cred_type, username, password)` — set device credentials
- `fsiem_cmdb_trigger_discovery(ip_range)` → discovery_id
- `fsiem_cmdb_poll_discovery(discovery_id)` → status dict
- `fsiem_org_list()` — list orgs (Service Provider only)
- `fsiem_org_add(name, description)` — add org (Service Provider only)

## Quick Example

```python
# Look up a device
device = fsiem_cmdb_get_device(ip="10.0.0.50")
print(device["deviceName"], device["deviceType"], device["os"])

# Discover a subnet
disc_id = fsiem_cmdb_trigger_discovery("192.168.1.0/24")
status = fsiem_cmdb_poll_discovery(disc_id)
```

## Additional Resources
- Full implementations and XML formats: [reference.md](reference.md)
