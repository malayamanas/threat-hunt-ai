---
name: fsiem-cmdb
description: Query and manage the FortiSIEM CMDB — devices, credentials, discovery, and organizations. Use when working with device inventory or asset data.
---
# Skill: CMDB Operations
# Query and manage the FortiSIEM Configuration Management Database

## Overview
FortiSIEM CMDB APIs use XML. Devices are identified by IP, hostname, or internal ID.
Base endpoint: `/phoenix/rest/cmdbDeviceInfo/`

---

## fsiem_cmdb_get_devices

```python
import requests
import xml.etree.ElementTree as ET

def fsiem_cmdb_get_devices(
    ip_range: str = None,         # e.g. "192.168.1.0/24" or "192.168.1.1"
    hostname: str = None,
    device_type: str = None,      # e.g. "Firewall", "Server", "Router"
    org: str = None,              # SP deployments only
    max_results: int = 500
) -> list[dict]:
    """
    List CMDB devices with optional filters.
    Returns list of device dicts.
    """
    from .auth import fsiem_auth_header, fsiem_base_url, fsiem_verify_ssl
    
    xml_body = "<DeviceInfoRequestObject>"
    if ip_range:
        xml_body += f"<includeIps>{ip_range}</includeIps>"
    if hostname:
        xml_body += f"<hostName>{hostname}</hostName>"
    if device_type:
        xml_body += f"<deviceType>{device_type}</deviceType>"
    if org:
        xml_body += f"<organization>{org}</organization>"
    xml_body += "</DeviceInfoRequestObject>"
    
    url = f"{fsiem_base_url()}/cmdbDeviceInfo/devices"
    resp = requests.post(
        url,
        data=xml_body,
        headers={**fsiem_auth_header(), "Content-Type": "text/xml"},
        verify=fsiem_verify_ssl()
    )
    resp.raise_for_status()
    
    root = ET.fromstring(resp.text)
    devices = []
    for dev in root.findall(".//device"):
        devices.append({
            "ip": dev.findtext("accessIp"),
            "name": dev.findtext("deviceName"),
            "type": dev.findtext("deviceType"),
            "vendor": dev.findtext("deviceVendor"),
            "model": dev.findtext("deviceModel"),
            "version": dev.findtext("deviceVersion"),
            "os": dev.findtext("os"),
            "org": dev.findtext("organization"),
            "approved": dev.findtext("approved"),
            "unmanaged": dev.findtext("unmanaged"),
        })
    return devices[:max_results]
```

---

## fsiem_cmdb_get_device

```python
def fsiem_cmdb_get_device(ip: str = None, hostname: str = None) -> dict:
    """Get complete CMDB information for a single device."""
    from .auth import fsiem_auth_header, fsiem_base_url, fsiem_verify_ssl
    
    url = f"{fsiem_base_url()}/cmdbDeviceInfo/device"
    params = {}
    if ip:
        params["ip"] = ip
    if hostname:
        params["hostname"] = hostname
    
    resp = requests.get(url, params=params,
                        headers=fsiem_auth_header(),
                        verify=fsiem_verify_ssl())
    resp.raise_for_status()
    root = ET.fromstring(resp.text)
    dev = root.find(".//device")
    if dev is None:
        return {}
    return {tag.tag: tag.text for tag in dev}
```

---

## fsiem_cmdb_get_device_apps

```python
def fsiem_cmdb_get_device_apps(ip: str) -> list[dict]:
    """Get application inventory for a device."""
    from .auth import fsiem_auth_header, fsiem_base_url, fsiem_verify_ssl
    
    url = f"{fsiem_base_url()}/cmdbDeviceInfo/device"
    params = {"ip": ip, "type": "applications"}
    resp = requests.get(url, params=params,
                        headers=fsiem_auth_header(),
                        verify=fsiem_verify_ssl())
    resp.raise_for_status()
    root = ET.fromstring(resp.text)
    return [{"name": a.findtext("name"), "version": a.findtext("version"),
             "port": a.findtext("port")} for a in root.findall(".//app")]
```

---

## fsiem_cmdb_set_credentials

```python
def fsiem_cmdb_set_credentials(
    ip: str,
    cred_type: str,       # e.g. "WMI", "SNMP", "SSH", "Telnet"
    username: str = None,
    password: str = None,
    community: str = None,   # for SNMP
    org: str = "super"
) -> bool:
    """Set or update device credentials in FortiSIEM."""
    from .auth import fsiem_auth_header, fsiem_base_url, fsiem_verify_ssl
    
    cred_block = f"<accessMethod>{cred_type}</accessMethod>"
    if username:
        cred_block += f"<userName>{username}</userName>"
    if password:
        cred_block += f"<password>{password}</password>"
    if community:
        cred_block += f"<community>{community}</community>"
    
    xml_body = f"""<DeviceCredential>
  <ipRange>{ip}</ipRange>
  <organization>{org}</organization>
  {cred_block}
</DeviceCredential>"""
    
    url = f"{fsiem_base_url()}/config/deviceCredential"
    resp = requests.post(url, data=xml_body,
                         headers={**fsiem_auth_header(), "Content-Type": "text/xml"},
                         verify=fsiem_verify_ssl())
    return resp.status_code == 200
```

---

## fsiem_cmdb_trigger_discovery

```python
def fsiem_cmdb_trigger_discovery(
    ip_range: str,
    org: str = "super",
    method: str = "ping"   # "ping", "snmp", "wmi", etc.
) -> str:
    """
    Trigger device discovery for an IP range.
    Returns a discovery job ID for polling.
    """
    from .auth import fsiem_auth_header, fsiem_base_url, fsiem_verify_ssl
    
    xml_body = f"""<DiscoveryRequest>
  <ipRange>{ip_range}</ipRange>
  <organization>{org}</organization>
  <discoverMethod>{method}</discoverMethod>
</DiscoveryRequest>"""
    
    url = f"{fsiem_base_url()}/cmdbDeviceInfo/discover"
    resp = requests.post(url, data=xml_body,
                         headers={**fsiem_auth_header(), "Content-Type": "text/xml"},
                         verify=fsiem_verify_ssl())
    resp.raise_for_status()
    root = ET.fromstring(resp.text)
    return root.findtext(".//discoveryId") or resp.text.strip()
```

---

## fsiem_cmdb_poll_discovery

```python
def fsiem_cmdb_poll_discovery(discovery_id: str) -> dict:
    """Poll the status of a discovery job."""
    from .auth import fsiem_auth_header, fsiem_base_url, fsiem_verify_ssl
    
    url = f"{fsiem_base_url()}/cmdbDeviceInfo/discoverStatus/{discovery_id}"
    resp = requests.get(url, headers=fsiem_auth_header(), verify=fsiem_verify_ssl())
    resp.raise_for_status()
    root = ET.fromstring(resp.text)
    return {
        "status": root.findtext(".//status"),
        "progress": root.findtext(".//progress"),
        "devicesFound": root.findtext(".//devicesFound"),
        "errors": root.findtext(".//errors"),
    }
```

---

## Organization Management (Service Provider)

```python
def fsiem_org_list() -> list[dict]:
    """List all organizations (SP deployments only)."""
    from .auth import fsiem_auth_header, fsiem_base_url, fsiem_verify_ssl
    
    url = f"{fsiem_base_url()}/config/Domain"
    resp = requests.get(url, headers=fsiem_auth_header(), verify=fsiem_verify_ssl())
    resp.raise_for_status()
    root = ET.fromstring(resp.text)
    return [{tag.tag: tag.text for tag in org} for org in root.findall(".//organization")]


def fsiem_org_add(
    name: str,
    description: str = "",
    admin_email: str = "",
    eps_limit: int = 1000
) -> bool:
    """Add a new organization to a Service Provider deployment."""
    from .auth import fsiem_auth_header, fsiem_base_url, fsiem_verify_ssl
    
    xml_body = f"""<organization>
  <name>{name}</name>
  <description>{description}</description>
  <adminEmail>{admin_email}</adminEmail>
  <epsLimit>{eps_limit}</epsLimit>
</organization>"""
    
    url = f"{fsiem_base_url()}/config/Domain"
    resp = requests.post(url, data=xml_body,
                         headers={**fsiem_auth_header(), "Content-Type": "text/xml"},
                         verify=fsiem_verify_ssl())
    return resp.status_code == 200
```
