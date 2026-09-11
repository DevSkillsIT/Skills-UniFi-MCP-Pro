# Permission System

The UniFi Network MCP server includes a comprehensive permission system that allows you to control which tools are available based on the risk level of their operations.

## Overview

Permissions are enforced at **decorator-level** during tool registration. Tools that don't meet the permission requirements are **never registered** with the MCP server, making them completely unavailable to LLMs.

This is a security-critical feature that prevents accidental or unauthorized modifications to your network infrastructure.

## How It Works

### 1. Permission Configuration

Permissions are configured in `src/config/config.yaml`:

```yaml
permissions:
  # Delete is refused unconditionally in parse_permission(), whatever this file
  # says. Removing a network, WLAN or firewall rule through an LLM is not a
  # reversible mistake, so the gate is in code rather than in configuration.

  default:
    create: true
    update: true

  networks:
    create: true   # Provisioning a new network can disrupt traffic
    update: true   # Changing subnets, VLANs, DHCP ranges requires care

  devices:
    create: true   # Adoption / provisioning
    update: true   # Reboot, firmware upgrade, rename

  events:
    create: false  # Events are read-only
    update: true   # Allow archiving alarms
```

Set a category to `false` to withhold it. A category with no entry falls back to
`default`; an action with no entry under `default` either is refused.

### 2. Tool Decorators

Tools specify their permission requirements using decorator parameters:

```python
@server.tool(
    name="unifi_create_network",
    description="Create a new network (LAN/VLAN)",
    permission_category="networks",
    permission_action="create"
)
async def create_network(network_data: dict):
    # This tool will NOT be registered if permissions.networks.create = false
    ...
```

### 3. Enforcement

The `permissioned_tool` decorator in `src/main.py` checks permissions **before** registering tools:

```python
# Check permission config
allowed = parse_permission(config.permissions, category, action)

if allowed:
    # Register tool with MCP server
    register_tool(...)
    return _original_tool_decorator(...)(func)
else:
    # Skip registration - tool won't be available
    logger.info("[permissions] Skipping registration of tool '%s'", tool_name)
    return func
```

## Permission Categories

| Category | Shipped default | Description |
|----------|-----------------|-------------|
| **networks** | ✅ Create / Update | Network and VLAN creation and modification (high risk) |
| **wlans** | ✅ Create / Update | Wireless network configuration (high risk) |
| **devices** | ✅ Create / Update | Device adoption, upgrades, reboots, radio changes (high risk) |
| **clients** | ✅ Update | Client blocking, reconnection, guest authorization, fixed IP (medium risk) |
| **firewall_policies** | ✅ Create / Update | Firewall policy management |
| **traffic_routes** | ✅ Create / Update | Policy-based routing (V2 API) |
| **routing** | ✅ Create / Update | Static routes (V1 API) |
| **port_forwards** | ✅ Create / Update | Port forwarding rules |
| **qos_rules** | ✅ Create / Update | Quality of Service rules |
| **vpn** | ✅ Create / Update | VPN configuration |
| **usergroups** | ✅ Create / Update | Bandwidth profiles / user groups |
| **vouchers** | ✅ Create / Update | Guest hotspot vouchers |
| **snmp** | ✅ Update | SNMP settings |
| **events** | ✅ Update, ❌ Create | Archiving alarms; events themselves are read-only |
| **system** | ❌ Admin | `unifi_restart_controller` needs `system.admin`, which no entry grants |

Every category resolves through the same chain, so a category absent from
`config.yaml` (such as `routing`, `vpn` or `snmp`) inherits `default`.

## Default Configuration Rationale

Two gates are absolute and sit in code rather than in configuration:

- **Delete is always refused.** `parse_permission()` returns `False` for the
  `delete` action before it reads the environment or the config file, so
  `unifi_delete_static_route`, `unifi_delete_traffic_route`,
  `unifi_delete_user_group` and `unifi_delete_vpn_config` are never registered.
- **An unmapped action is refused.** Only `read` is allowed when neither the
  category nor `default` names the action.

Everything else is a configuration decision, and the shipped `config.yaml`
grants create and update broadly. Withhold the categories whose blast radius
you are not willing to hand an agent:

- **networks**: Creating/modifying networks can cause network outages
- **wlans**: Wireless changes can disconnect all Wi-Fi clients
- **devices**: Reboots, adoptions and upgrades cause downtime
- **clients**: Client operations affect user connectivity

## Enabling Permissions

You can enable permissions in three ways (in priority order):

### 1. Environment Variables (Highest Priority) ⭐ **RECOMMENDED**

Enable specific permissions at runtime without modifying config files:

```bash
# Enable network creation
export UNIFI_PERMISSIONS_NETWORKS_CREATE=true
export UNIFI_PERMISSIONS_NETWORKS_UPDATE=true

# Enable device management
export UNIFI_PERMISSIONS_DEVICES_CREATE=true
export UNIFI_PERMISSIONS_DEVICES_UPDATE=true

# Enable client operations
export UNIFI_PERMISSIONS_CLIENTS_UPDATE=true
```

**For Claude Desktop**, add to your MCP server config:

```json
{
  "mcpServers": {
    "unifi": {
      "command": "uv",
      "args": ["--directory", "/path/to/unifi-network-mcp", "run", "python", "-m", "src.main"],
      "env": {
        "UNIFI_HOST": "192.168.1.1",
        "UNIFI_USERNAME": "admin",
        "UNIFI_PASSWORD": "password",
        "UNIFI_PERMISSIONS_NETWORKS_CREATE": "true",
        "UNIFI_PERMISSIONS_DEVICES_UPDATE": "true"
      }
    }
  }
}
```

### 2. Config File

Modify `src/config/config.yaml`:

```yaml
permissions:
  networks:
    create: true
    update: true

  devices:
    create: true
    update: true
```

### 3. Default Permissions

Falls back to the defaults in config.yaml if no overrides are set.

## Permission Variable Names

Environment variables follow the pattern: `UNIFI_PERMISSIONS_<CATEGORY>_<ACTION>`

| Category | Create Variable | Update Variable |
|----------|----------------|-----------------|
| **networks** | `UNIFI_PERMISSIONS_NETWORKS_CREATE` | `UNIFI_PERMISSIONS_NETWORKS_UPDATE` |
| **wlans** | `UNIFI_PERMISSIONS_WLANS_CREATE` | `UNIFI_PERMISSIONS_WLANS_UPDATE` |
| **devices** | `UNIFI_PERMISSIONS_DEVICES_CREATE` | `UNIFI_PERMISSIONS_DEVICES_UPDATE` |
| **clients** | N/A | `UNIFI_PERMISSIONS_CLIENTS_UPDATE` |
| **firewall_policies** | `UNIFI_PERMISSIONS_FIREWALL_POLICIES_CREATE` | `UNIFI_PERMISSIONS_FIREWALL_POLICIES_UPDATE` |
| **traffic_routes** | `UNIFI_PERMISSIONS_TRAFFIC_ROUTES_CREATE` | `UNIFI_PERMISSIONS_TRAFFIC_ROUTES_UPDATE` |
| **port_forwards** | `UNIFI_PERMISSIONS_PORT_FORWARDS_CREATE` | `UNIFI_PERMISSIONS_PORT_FORWARDS_UPDATE` |
| **qos_rules** | `UNIFI_PERMISSIONS_QOS_RULES_CREATE` | `UNIFI_PERMISSIONS_QOS_RULES_UPDATE` |
| **routing** | `UNIFI_PERMISSIONS_ROUTING_CREATE` | `UNIFI_PERMISSIONS_ROUTING_UPDATE` |
| **usergroups** | `UNIFI_PERMISSIONS_USERGROUPS_CREATE` | `UNIFI_PERMISSIONS_USERGROUPS_UPDATE` |
| **vouchers** | `UNIFI_PERMISSIONS_VOUCHERS_CREATE` | `UNIFI_PERMISSIONS_VOUCHERS_UPDATE` |
| **vpn** | `UNIFI_PERMISSIONS_VPN_CREATE` | `UNIFI_PERMISSIONS_VPN_UPDATE` |
| **events** | `UNIFI_PERMISSIONS_EVENTS_CREATE` | `UNIFI_PERMISSIONS_EVENTS_UPDATE` |
| **snmp** | N/A | `UNIFI_PERMISSIONS_SNMP_UPDATE` |

`unifi_restart_controller` is gated on `system` / `admin`, so its variable is
`UNIFI_PERMISSIONS_SYSTEM_ADMIN`.

**Accepted Values:** `true`, `1`, `yes`, `on` (case-insensitive) = enabled; anything else = disabled

## Impact on Tool Discovery and Availability

**Important:** Permissions decide **registration**, not the contents of the manifest.

The tool manifest (`tools_manifest.json`) lists the whole catalog regardless of permission settings. This ensures:

1. ✅ **Users control permissions** via their own config.yaml
2. ✅ **LLMs can discover all tools** via `unifi_tool_index`
3. ✅ **Withheld tools appear in the index marked `callable: false`**
4. ✅ **Withheld tools are never registered, so they cannot be invoked**

`unifi_tool_index` reports the live count alongside `callable_count` and a
`blocked_by_permissions` list, so it answers "what can this server actually do"
without anyone having to keep a number in prose up to date.

### How It Works

When the server starts:

1. **All tools registered in TOOL_REGISTRY** (for discovery)
2. **Permission check determines MCP registration**:
   - ✅ Allowed: Tool is callable via MCP
   - ❌ Denied: Tool appears in the index flagged `callable: false` and is not registered

Example server startup output:

```
[permissions] Skipping MCP registration of tool 'unifi_delete_static_route' (category=routing, action=delete)
[permissions] Skipping MCP registration of tool 'unifi_restart_controller' (category=system, action=admin)
...
```

### User Experience

**If a tool is withheld:**
- ✅ Appears in `unifi_tool_index` results, flagged `callable: false`
- ❌ Cannot be called via MCP (never registered with the server)
- 💡 The LLM sees it exists but cannot invoke it

**Why this design:**
- Users configure their own permissions
- Tool manifest is consistent across installations
- No rebuild required when changing permissions
- Clear feedback about what's available vs. what's allowed

## Security Benefits

1. **Defense in Depth** - Permissions enforced at multiple levels:
   - Build time (manifest generation)
   - Runtime (decorator evaluation)

2. **Fail-Safe Defaults** - High-risk operations disabled by default

3. **Visibility** - Clear logging of permission decisions

4. **Atomic Control** - Enable/disable entire categories at once

## Permission Actions

| Action | Typical Operations |
|--------|-------------------|
| **create** | Add new resources (networks, rules, etc.) |
| **update** | Modify existing resources (rename, toggle, change config) |
| **delete** | Remove resources. Refused unconditionally |
| **admin** | Controller-level operations such as restarting the controller |

Note: `delete` is not a permission you can grant. `parse_permission()` returns
`False` for it before consulting the environment or the config file, so the four
delete tools are never registered no matter what any file says.

## Tools by Permission

Read-only tools carry no permission requirement and are always registered.
The tools below are gated; `unifi_tool_index` reports which ones the running
server accepted.

### Networks (`networks`)
- `unifi_create_network` (create)
- `unifi_update_network` (update)
- `unifi_list_networks`, `unifi_get_network_details` (no permission required)

### WLANs (`wlans`)
- `unifi_create_wlan` (create)
- `unifi_update_wlan` (update)
- `unifi_list_wlans`, `unifi_get_wlan_details` (no permission required)

### Devices (`devices`)
- `unifi_manage_device` — registration is gated on `devices.update`. The
  `adopt` action additionally requires `devices.create`; `reboot`, `rename`,
  `locate`, `upgrade` and `set_radio` require `devices.update`. Folding several
  operations behind one tool does not widen what the permission file allows.
- `unifi_list_devices`, `unifi_get_device_details` (no permission required)

### Clients (`clients`)
- `unifi_block_client`, `unifi_unblock_client`, `unifi_force_reconnect_client`,
  `unifi_authorize_guest`, `unifi_unauthorize_guest`,
  `unifi_set_client_ip_settings` (update)
- `unifi_list_clients`, `unifi_get_client_details`, `unifi_rename_client`,
  `unifi_lookup_by_ip` (no permission check)

### Firewall Policies (`firewall_policies`)
- `unifi_create_firewall_policy` (create)
- `unifi_update_firewall_policy`, `unifi_toggle_firewall_policy` (update)

### Traffic Routes (`traffic_routes`)
- `unifi_create_traffic_route` (create)
- `unifi_update_traffic_route` (update)
- `unifi_delete_traffic_route` (delete — always refused)

### Static Routes (`routing`)
- `unifi_create_static_route` (create)
- `unifi_update_static_route` (update)
- `unifi_delete_static_route` (delete — always refused)

### Port Forwards (`port_forwards`)
- `unifi_create_port_forward` (create)
- `unifi_update_port_forward`, `unifi_toggle_port_forward` (update)

### QoS Rules (`qos_rules`)
- `unifi_create_qos_rule` (create)
- `unifi_update_qos_rule`, `unifi_toggle_qos_rule_enabled` (update)

### VPN (`vpn`)
- `unifi_create_vpn_config` (create)
- `unifi_update_vpn_config` (update)
- `unifi_delete_vpn_config` (delete — always refused)

### User Groups (`usergroups`)
- `unifi_create_user_group` (create)
- `unifi_update_user_group` (update)
- `unifi_delete_user_group` (delete — always refused)

### Vouchers (`vouchers`)
- `unifi_create_voucher` (create)
- `unifi_revoke_voucher` (update)

### Events (`events`)
- `unifi_archive_alarm`, `unifi_archive_all_alarms` (update)
- `unifi_list_events`, `unifi_list_alarms`, `unifi_get_event_types`
  (no permission required)

### System
- `unifi_update_snmp_settings` (`snmp.update`)
- `unifi_restart_controller` (`system.admin`)

## Best Practices

1. **Start Conservative** - Use default permissions initially
2. **Enable Selectively** - Only enable what you need
3. **Test First** - Enable in dev/test environments before production
4. **Document Changes** - Track permission changes in version control
5. **Review Regularly** - Audit enabled permissions periodically

## Troubleshooting

### Tool Listed but Not Callable

**Symptom:** A tool appears in `unifi_tool_index` flagged `callable: false`, or
in the `blocked_by_permissions` list, and the client does not offer it

**Cause:** Its permission resolved to `false`, so it was never registered

**Solution:**
1. Check the category and action in the table above
2. Set `UNIFI_PERMISSIONS_<CATEGORY>_<ACTION>=true`, or enable it in
   `src/config/config.yaml`
3. Restart the MCP server

A `delete` tool cannot be recovered this way: the refusal is in code.

### Permission Denied at Runtime

**Symptom:** "Permission denied" error when calling a tool

**Cause:** Some tools have additional runtime permission checks

**Solution:** Check both:
- Decorator permissions (config.yaml)
- Runtime permission checks (within tool function)

## Future Enhancements

Planned for future releases:

1. **Fine-grained permissions** - Per-tool overrides
2. **Permission profiles** - Predefined sets (e.g., "read-only", "power-user")
3. **Dynamic permissions** - Runtime permission changes without restart
4. **Audit logging** - Track all permission-gated operations

## Confirmation System

All mutating tools (create, update, toggle operations) implement a **preview-then-confirm** pattern for safety:

### How It Works

1. **Without confirmation** (`confirm=false`, the default): Tool returns a preview of what will change
2. **With confirmation** (`confirm=true`): Tool executes the operation

**Example preview response:**
```json
{
  "success": false,
  "requires_confirmation": true,
  "action": "toggle",
  "resource_type": "port_forward",
  "resource_id": "abc123",
  "resource_name": "SSH Access",
  "preview": {
    "current": {"enabled": true},
    "proposed": {"enabled": false}
  },
  "message": "Will disable port_forward 'SSH Access'. Set confirm=true to execute."
}
```

This gives LLM agents context to make informed decisions before executing changes.

### Three Levels of Confirmation Control

| Level | Method | Use Case |
|-------|--------|----------|
| **Per-call** | Pass `confirm=true` in tool arguments | LLM explicitly confirms each operation |
| **Per-session** | System prompt instructs agent to auto-confirm | Agent follows user's standing instructions |
| **Per-environment** | `UNIFI_AUTO_CONFIRM=true` env var | Workflow automation (n8n, Make, Zapier) |

### Auto-Confirm for Workflow Automation

For workflow automation tools where the two-step confirmation adds unnecessary complexity:

**Environment variable:**
```bash
export UNIFI_AUTO_CONFIRM=true
```

**Docker:**
```bash
docker run -e UNIFI_AUTO_CONFIRM=true ...
```

**Claude Desktop / n8n:**
```json
{
  "env": {
    "UNIFI_AUTO_CONFIRM": "true"
  }
}
```

When `UNIFI_AUTO_CONFIRM=true`:
- Reversible mutating operations execute immediately
- Preview step is skipped for them
- No changes to your workflow logic required

**Accepted values:** `true`, `1`, `yes`, `on` (case-insensitive)

### Actions That Always Require Confirmation

`reboot`, `restart`, `upgrade`, `adopt`, `restore` and `set_radio` ignore
`UNIFI_AUTO_CONFIRM` entirely and always require `confirm=true` in the call.
They take effect at once and no later call undoes them; a radio change is on
that list because it re-provisions the access point and drops every wireless
client on the band.

### Dev Console Behavior

The developer console (`devtools/dev_console.py`) automatically sets `confirm=true` for testing convenience, displaying a warning:

```
⚠️  DEV CONSOLE: Auto-setting confirm=true for testing
   (In production, LLMs must explicitly confirm operations)
```

This makes testing faster while reminding developers about production behavior.

## Related Documentation

- [Configuration Guide](configuration.md)
- [Security Best Practices](security.md)
- [Tool Index API](tool-index.md)
