from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set

from models import ConflictItem, ConflictPolicy, Policy, PolicyType

logger = logging.getLogger(__name__)

# ── Friendly name mappings ───────────────────────────────────────────────────

# Common Device Configuration / Compliance property → friendly name
_DEVICE_CONFIG_NAMES: Dict[str, str] = {
    "passwordRequired": "Require Password",
    "passwordMinimumLength": "Minimum Password Length",
    "passwordBlockSimple": "Block Simple Passwords",
    "passwordRequiredType": "Required Password Type",
    "passwordMinutesOfInactivityBeforeLock": "Minutes of Inactivity Before Lock",
    "passwordExpirationDays": "Password Expiration (Days)",
    "passwordPreviousPasswordBlockCount": "Previous Passwords Blocked",
    "passwordMinimumCharacterSetCount": "Minimum Character Sets",
    "passwordRequiredToUnlockFromIdle": "Require Password to Unlock from Idle",
    "firewallEnabled": "Enable Firewall",
    "firewallBlockAllIncoming": "Block All Incoming Connections",
    "firewallEnableStealthMode": "Enable Stealth Mode",
    "firewallProfileDomain": "Firewall Domain Profile",
    "firewallProfilePrivate": "Firewall Private Profile",
    "firewallProfilePublic": "Firewall Public Profile",
    "bitLockerEnabled": "Enable BitLocker",
    "bitLockerAllowStandardUserEncryption": "Allow Standard User Encryption",
    "bitLockerSystemDrivePolicy": "BitLocker System Drive Policy",
    "bitLockerFixedDrivePolicy": "BitLocker Fixed Drive Policy",
    "bitLockerRemovableDrivePolicy": "BitLocker Removable Drive Policy",
    "defenderEnabled": "Enable Defender",
    "defenderRequireRealTimeMonitoring": "Require Real-Time Monitoring",
    "defenderScanType": "Defender Scan Type",
    "defenderScheduledScanTime": "Scheduled Scan Time",
    "defenderCloudBlockLevel": "Cloud Block Level",
    "defenderPotentiallyUnwantedAppAction": "Potentially Unwanted App Action",
    "defenderSubmitSamplesConsentType": "Submit Samples Consent",
    "storageRequireEncryption": "Require Storage Encryption",
    "storageRequireDeviceEncryption": "Require Device Encryption",
    "securityBlockJailbrokenDevices": "Block Jailbroken Devices",
    "deviceThreatProtectionEnabled": "Enable Threat Protection",
    "deviceThreatProtectionRequiredSecurityLevel": "Required Threat Protection Level",
    "osMinimumVersion": "Minimum OS Version",
    "osMaximumVersion": "Maximum OS Version",
    "osMinimumBuildVersion": "Minimum OS Build Version",
    "osMaximumBuildVersion": "Maximum OS Build Version",
    "earlyLaunchAntiMalwareDriverEnabled": "Early Launch Anti-Malware Driver",
    "secureBootEnabled": "Require Secure Boot",
    "codeIntegrityEnabled": "Require Code Integrity",
    "tpmRequired": "Require TPM",
    "activeFirewallRequired": "Require Active Firewall",
    "antiSpywareRequired": "Require Anti-Spyware",
    "antivirusRequired": "Require Antivirus",
    "realTimeProtectionEnabled": "Require Real-Time Protection",
    "signatureOutOfDate": "Block Outdated Signatures",
    "rtpEnabled": "Real-Time Protection",
    "avEnabled": "Antivirus Enabled",
    "windowsHealthMonitoring": "Windows Health Monitoring",
    "configurationProfileBlockChanges": "Block Configuration Profile Changes",
    "compliantAppsList": "Compliant Apps List",
    "appsBlockClipboardSharing": "Block Clipboard Sharing",
    "appsBlockCopyPaste": "Block Copy/Paste",
    "appsBlockYouTube": "Block YouTube",
    "cameraBlocked": "Block Camera",
    "cellularBlockDataRoaming": "Block Data Roaming",
    "cellularBlockMessaging": "Block Messaging",
    "cellularBlockVoiceRoaming": "Block Voice Roaming",
    "cellularBlockWiFiTethering": "Block WiFi Tethering",
    "diagnosticDataBlockSubmission": "Block Diagnostic Data Submission",
    "locationServicesBlocked": "Block Location Services",
    "screenCaptureBlocked": "Block Screen Capture",
    "bluetoothBlocked": "Block Bluetooth",
    "nfcBlocked": "Block NFC",
    "wifiBlocked": "Block WiFi",
    "wifiBlockAutomaticConnectHotspots": "Block Auto-Connect Hotspots",
    "wifiBlockManualConfiguration": "Block Manual WiFi Configuration",
    "edgeBlocked": "Block Edge Browser",
    "edgeCookiePolicy": "Edge Cookie Policy",
    "edgeBlockPopups": "Edge Block Popups",
    "edgeBlockSearchSuggestions": "Edge Block Search Suggestions",
    "edgeSendIntranetTrafficToInternetExplorer": "Send Intranet Traffic to IE",
    "internetSharingBlocked": "Block Internet Sharing",
    "settingsBlockEditDeviceName": "Block Edit Device Name",
    "settingsBlockAddProvisioningPackage": "Block Add Provisioning Package",
    "settingsBlockRemoveProvisioningPackage": "Block Remove Provisioning Package",
    "experienceBlockDeviceDiscovery": "Block Device Discovery",
    "experienceBlockTaskSwitcher": "Block Task Switcher",
    "experienceBlockErrorDialogWhenNoSIM": "Block Error Dialog When No SIM",
    "startBlockUnpinningAppsFromTaskbar": "Block Unpinning Apps from Taskbar",
    "windowsSpotlightBlocked": "Block Windows Spotlight",
    "windowsStoreBlocked": "Block Windows Store",
    "windowsStoreEnablePrivateStoreOnly": "Enable Private Store Only",
    "searchBlockDiacritics": "Block Diacritics in Search",
    "searchDisableAutoLanguageDetection": "Disable Auto Language Detection",
    "searchDisableIndexingEncryptedItems": "Disable Indexing Encrypted Items",
    "searchDisableIndexerBackoff": "Disable Indexer Backoff",
    "updateServiceUrl": "Windows Update Service URL",
}

# Conditional Access grant control mapping
_CA_GRANT_CONTROLS: Dict[str, str] = {
    "mfa": "Require MFA",
    "compliantDevice": "Require Compliant Device",
    "domainJoinedDevice": "Require Hybrid Azure AD Joined Device",
    "approvedApplication": "Require Approved Client App",
    "compliantApplication": "Require App Protection Policy",
    "passwordChange": "Require Password Change",
    "block": "Block Access",
}

# Conditional Access condition friendly names
_CA_CONDITION_NAMES: Dict[str, str] = {
    "users": "Users & Groups",
    "applications": "Cloud Apps",
    "clientAppTypes": "Client App Types",
    "locations": "Locations",
    "platforms": "Device Platforms",
    "devices": "Device Filters",
    "signInRiskLevels": "Sign-in Risk Levels",
    "userRiskLevels": "User Risk Levels",
    "servicePrincipalRiskLevels": "Service Principal Risk Levels",
}

# Metadata fields to skip when extracting settings from raw policy dicts
_RAW_SKIP_FIELDS: Set[str] = {
    "id",
    "displayName",
    "name",
    "description",
    "@odata.type",
    "@odata.context",
    "createdDateTime",
    "lastModifiedDateTime",
    "version",
    "assignments",
    "roleScopeTagIds",
    "supportsScopeTags",
    "deviceManagementApplicabilityRuleOsEdition",
    "deviceManagementApplicabilityRuleOsVersion",
    "deviceManagementApplicabilityRuleDeviceMode",
    "isAssigned",
    "platforms",
    "platformType",
    "platform",
    "technologies",
    "settingCount",
    "templateReference",
}


# ── Helpers ──────────────────────────────────────────────────────────────────


def _camel_to_title(name: str) -> str:
    """Convert camelCase to Title Case With Spaces."""
    s = re.sub(r"([A-Z])", r" \1", name)
    return s.strip().title()


def _friendly_name_for_property(key: str) -> str:
    """Get a friendly display name for a device config / compliance property."""
    if key in _DEVICE_CONFIG_NAMES:
        return _DEVICE_CONFIG_NAMES[key]
    return _camel_to_title(key)


def _format_value_display(value: Any) -> str:
    """Return a human-readable display string for a setting value."""
    if value is None:
        return "Not Configured"
    if isinstance(value, bool):
        return "Enabled" if value else "Disabled"
    if isinstance(value, str):
        low = value.lower()
        if low in ("true", "yes"):
            return "Enabled"
        if low in ("false", "no"):
            return "Disabled"
        if low == "notconfigured":
            return "Not Configured"
        # For enum-like values ending in _enabled/_disabled/_required etc.
        if "_" in value:
            return value.replace("_", " ").title()
        return value
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        if not value:
            return "None"
        if all(isinstance(v, str) for v in value):
            return ", ".join(value)
        return json.dumps(value, indent=2)
    if isinstance(value, dict):
        return json.dumps(value, indent=2)
    return str(value)


def _normalize_value(value: Any) -> Any:
    """Normalize a value for comparison — canonical form for bools, None, etc."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        low = value.lower()
        if low in ("true", "yes"):
            return True
        if low in ("false", "no"):
            return False
        if low == "notconfigured":
            return None
        return value
    if isinstance(value, list):
        return [_normalize_value(v) for v in value]
    if isinstance(value, dict):
        return {k: _normalize_value(v) for k, v in value.items()}
    return value


# ── Setting extraction per policy type ───────────────────────────────────────


def _make_entry(
    setting_key: str,
    display_name: str,
    value: Any,
    policy: Policy,
    policy_type_str: str,
) -> Dict[str, Any]:
    """Build a standardized setting entry dict."""
    norm = _normalize_value(value)
    return {
        "setting_key": setting_key,
        "display_name": display_name,
        "value": norm,
        "value_display": _format_value_display(norm),
        "policy_id": policy.id,
        "policy_name": policy.display_name,
        "policy_type": policy_type_str,
    }


def _extract_raw_settings(policy: Policy, prefix: str) -> List[Dict[str, Any]]:
    """Extract settings from the raw dict (Device Config, Compliance, etc.)."""
    results: List[Dict[str, Any]] = []
    raw = policy.raw
    for key, value in raw.items():
        if key.startswith("@") or key in _RAW_SKIP_FIELDS:
            continue
        norm = _normalize_value(value)
        if norm is None:
            continue
        setting_key = f"{prefix}:{key}"
        display_name = _friendly_name_for_property(key)
        results.append(
            _make_entry(setting_key, display_name, value, policy, prefix)
        )
    return results


def _extract_settings_catalog(policy: Policy) -> List[Dict[str, Any]]:
    """Extract settings from Settings Catalog / Compliance v2 policies."""
    results: List[Dict[str, Any]] = []
    prefix = policy.policy_type.value
    for setting in policy.settings:
        instance = setting.get("settingInstance", {})
        odata_type = instance.get("@odata.type", "")
        definition_id = instance.get("settingDefinitionId", "")
        if not definition_id:
            continue

        # Try to get friendly name from embedded settingDefinitions
        display_name = _resolve_catalog_display_name(setting, definition_id)

        # Extract value based on setting instance type
        value = _extract_setting_instance_value(instance, odata_type)

        setting_key = f"{prefix}:{definition_id}"
        results.append(
            _make_entry(setting_key, display_name, value, policy, prefix)
        )
    return results


def _resolve_catalog_display_name(
    setting: Dict[str, Any], definition_id: str
) -> str:
    """Get the display name from settingDefinitions if available."""
    definitions = setting.get("settingDefinitions", [])
    if definitions:
        # Match by definitionId or just take the first that looks right
        for defn in definitions:
            if defn.get("id", "") == definition_id:
                name = defn.get("displayName", "")
                if name:
                    return name
        # Fallback: use the first definition's displayName
        first_name = definitions[0].get("displayName", "")
        if first_name:
            return first_name

    # Fallback: extract a readable name from the definition ID
    # Format: device_vendor_msft_policy_config_<category>_<setting>
    parts = definition_id.rsplit("_", 1)
    if len(parts) > 1:
        return _camel_to_title(parts[-1])
    return definition_id


def _extract_setting_instance_value(
    instance: Dict[str, Any], odata_type: str
) -> Any:
    """Extract the value from a setting instance based on its @odata.type."""
    type_lower = odata_type.lower()
    if "choicesettinginstance" in type_lower:
        choice_val = instance.get("choiceSettingValue", {})
        return choice_val.get("value")
    if "simplesettinginstance" in type_lower:
        simple_val = instance.get("simpleSettingValue", {})
        return simple_val.get("value")
    if "simplesettingcollectioninstance" in type_lower:
        collection = instance.get("simpleSettingCollectionValue", [])
        return [v.get("value") for v in collection]
    if "groupsettinginstance" in type_lower:
        group_val = instance.get("groupSettingValue", {})
        children = group_val.get("children", [])
        return {
            c.get("settingDefinitionId", ""): _extract_setting_instance_value(
                c, c.get("@odata.type", "")
            )
            for c in children
        }
    # Fallback: return what we can find
    for k, v in instance.items():
        if k.endswith("Value") and k != "@odata.type":
            return v
    return None


def _extract_endpoint_security(policy: Policy) -> List[Dict[str, Any]]:
    """Extract settings from Endpoint Security intents (category-based)."""
    results: List[Dict[str, Any]] = []
    prefix = policy.policy_type.value
    for setting in policy.settings:
        definition_id = setting.get("definitionId", "")
        if not definition_id:
            continue

        # Use category display name + definition if available
        cat_name = setting.get("_categoryDisplayName", "")
        display_name = setting.get("displayName", "")
        if not display_name:
            # Try to extract from definitionId
            parts = definition_id.rsplit("_", 1)
            display_name = _camel_to_title(parts[-1]) if len(parts) > 1 else definition_id
        if cat_name and display_name:
            display_name = f"{cat_name} › {display_name}"

        value = setting.get("valueJson") or setting.get("value")
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except (json.JSONDecodeError, ValueError):
                pass

        setting_key = f"{prefix}:{definition_id}"
        results.append(
            _make_entry(setting_key, display_name, value, policy, prefix)
        )
    return results


def _extract_group_policy_admx(policy: Policy) -> List[Dict[str, Any]]:
    """Extract settings from Group Policy (ADMX) configurations."""
    results: List[Dict[str, Any]] = []
    prefix = policy.policy_type.value
    for setting in policy.settings:
        def_id = setting.get("id", "")
        enabled = setting.get("enabled")
        definition = setting.get("definition", {})
        display_name = definition.get("displayName", "")
        if not display_name:
            display_name = _camel_to_title(def_id) if def_id else "Unknown Setting"

        setting_key = f"{prefix}:{def_id}"
        results.append(
            _make_entry(setting_key, display_name, enabled, policy, prefix)
        )
    return results


def _extract_conditional_access(policy: Policy) -> List[Dict[str, Any]]:
    """Extract settings from Conditional Access policies."""
    results: List[Dict[str, Any]] = []
    prefix = policy.policy_type.value
    raw = policy.raw

    conditions = raw.get("conditions", {})
    for cond_key, cond_val in conditions.items():
        norm = _normalize_value(cond_val)
        if norm is None:
            continue
        setting_key = f"{prefix}:conditions.{cond_key}"
        display_name = _CA_CONDITION_NAMES.get(cond_key, _camel_to_title(cond_key))
        results.append(
            _make_entry(setting_key, display_name, cond_val, policy, prefix)
        )

    grant_controls = raw.get("grantControls")
    if grant_controls:
        setting_key = f"{prefix}:grantControls"
        # Build friendly display from builtInControls
        built_in = grant_controls.get("builtInControls", [])
        friendly_controls = [
            _CA_GRANT_CONTROLS.get(c, _camel_to_title(c)) for c in built_in
        ]
        operator = grant_controls.get("operator", "OR")
        display_name = "Grant Controls"
        value_display_parts = friendly_controls if friendly_controls else ["Custom Controls"]
        entry = _make_entry(setting_key, display_name, grant_controls, policy, prefix)
        entry["value_display"] = f" {operator} ".join(value_display_parts)
        results.append(entry)

    session_controls = raw.get("sessionControls")
    if session_controls:
        setting_key = f"{prefix}:sessionControls"
        display_name = "Session Controls"
        results.append(
            _make_entry(setting_key, display_name, session_controls, policy, prefix)
        )

    return results


def _extract_settings(policy: Policy) -> List[Dict[str, Any]]:
    """Extract normalized settings from any policy type.

    Returns list of dicts with keys:
        setting_key, display_name, value, value_display,
        policy_id, policy_name, policy_type
    """
    try:
        ptype = policy.policy_type

        if ptype in (PolicyType.DEVICE_CONFIGURATION, PolicyType.COMPLIANCE):
            return _extract_raw_settings(policy, ptype.value)

        if ptype in (PolicyType.SETTINGS_CATALOG, PolicyType.COMPLIANCE_V2):
            return _extract_settings_catalog(policy)

        if ptype == PolicyType.ENDPOINT_SECURITY:
            return _extract_endpoint_security(policy)

        if ptype == PolicyType.GROUP_POLICY_ADMX:
            return _extract_group_policy_admx(policy)

        if ptype == PolicyType.CONDITIONAL_ACCESS:
            return _extract_conditional_access(policy)

        if ptype in (
            PolicyType.APP_PROTECTION,
            PolicyType.APP_CONFIGURATION,
            PolicyType.AUTOPILOT,
            PolicyType.POWERSHELL_SCRIPTS,
            PolicyType.REMEDIATION_SCRIPTS,
        ):
            return _extract_raw_settings(policy, ptype.value)

    except Exception as e:
        logger.warning(
            "Failed to extract settings from policy %s (%s): %s",
            policy.id,
            policy.display_name,
            e,
        )
    return []


# ── Assignment overlap detection ─────────────────────────────────────────────


def _get_assigned_group_ids(policy: Policy) -> Set[str]:
    """Get set of included group IDs from a policy's assignments."""
    group_ids: Set[str] = set()
    has_all = False
    for assignment in policy.assignments:
        target = assignment.get("target", {})
        odata_type = target.get("@odata.type", "")
        group_id = target.get("groupId", "")
        if group_id and "exclusion" not in odata_type.lower():
            group_ids.add(group_id)
        if "allLicensedUsers" in odata_type or "allDevices" in odata_type:
            has_all = True
    if has_all:
        group_ids.add("__ALL__")
    return group_ids


def _policies_have_overlapping_assignments(
    policy_a: Policy, policy_b: Policy
) -> bool:
    """Check if two policies have at least one overlapping group assignment."""
    groups_a = _get_assigned_group_ids(policy_a)
    groups_b = _get_assigned_group_ids(policy_b)
    if not groups_a or not groups_b:
        return False
    if "__ALL__" in groups_a or "__ALL__" in groups_b:
        return True
    return bool(groups_a & groups_b)


# ── Conflict analysis ────────────────────────────────────────────────────────


def _build_conflicts(policies: List[Policy]) -> List[ConflictItem]:
    """Given a list of policies, find shared settings and classify conflicts vs duplicates."""
    settings_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for policy in policies:
        extracted = _extract_settings(policy)
        for s in extracted:
            settings_map[s["setting_key"]].append(s)

    conflicts: List[ConflictItem] = []

    for setting_key, entries in settings_map.items():
        if len(entries) < 2:
            continue

        # De-duplicate by policy_id
        seen_policy_ids: Set[str] = set()
        unique_entries: List[Dict[str, Any]] = []
        for entry in entries:
            if entry["policy_id"] not in seen_policy_ids:
                seen_policy_ids.add(entry["policy_id"])
                unique_entries.append(entry)

        if len(unique_entries) < 2:
            continue

        # Check if values differ
        values = [entry["value"] for entry in unique_entries]
        has_different = len(set(repr(v) for v in values)) > 1

        conflict_policies = [
            ConflictPolicy(
                policy_id=entry["policy_id"],
                policy_name=entry["policy_name"],
                policy_type=entry["policy_type"],
                value=entry["value"],
                value_display=entry.get("value_display", ""),
            )
            for entry in unique_entries
        ]

        # Use display_name from first entry
        display_name = unique_entries[0].get("display_name", "")

        conflicts.append(
            ConflictItem(
                setting_key=setting_key,
                setting_label=display_name,
                has_different_values=has_different,
                policies=conflict_policies,
            )
        )

    # Sort: true conflicts first, then by number of affected policies descending
    conflicts.sort(
        key=lambda c: (not c.has_different_values, -len(c.policies)),
    )

    return conflicts


def analyze_conflicts_for_group(
    group_id: str,
    all_policies: List[Policy],
    group_policy_mappings: List[Dict[str, Any]],
) -> List[ConflictItem]:
    """Find setting conflicts among policies targeting a specific group."""
    policy_ids: Set[str] = set()
    for mapping in group_policy_mappings:
        policies_in_mapping = mapping.get("policies", [])
        for p in policies_in_mapping:
            pid = p.get("id") or (p.id if isinstance(p, Policy) else "")
            if pid:
                policy_ids.add(pid)

    targeted = [p for p in all_policies if p.id in policy_ids]

    if len(targeted) < 2:
        return []

    return _build_conflicts(targeted)


def analyze_conflicts_for_target(
    target: str, all_policies: List[Policy]
) -> List[ConflictItem]:
    """Find conflicts among policies assigned to a special target ('all_users' or 'all_devices')."""
    if target == "all_users":
        odata_match = "allLicensedUsers"
    elif target == "all_devices":
        odata_match = "allDevices"
    else:
        return []

    targeted: List[Policy] = []
    for policy in all_policies:
        for assignment in policy.assignments:
            t = assignment.get("target", {})
            if odata_match in t.get("@odata.type", ""):
                targeted.append(policy)
                break

    if len(targeted) < 2:
        return []

    return _build_conflicts(targeted)


def analyze_conflicts_for_policy(
    policy_id: str, all_policies: List[Policy]
) -> List[ConflictItem]:
    """Find setting conflicts for a specific policy against all others."""
    target_policy = None
    for p in all_policies:
        if p.id == policy_id:
            target_policy = p
            break
    if not target_policy:
        return []

    target_groups = _get_assigned_group_ids(target_policy)

    # Find all policies that share at least one assignment group with the target
    related_policies = [target_policy]
    for p in all_policies:
        if p.id == policy_id:
            continue
        p_groups = _get_assigned_group_ids(p)
        if target_groups & p_groups:
            related_policies.append(p)

    if len(related_policies) < 2:
        return []

    # Build conflicts but only return items where the target policy is involved
    all_conflicts = _build_conflicts(related_policies)
    return [
        c for c in all_conflicts
        if any(cp.policy_id == policy_id for cp in c.policies)
    ]


def analyze_all_conflicts(all_policies: List[Policy]) -> List[ConflictItem]:
    """Find setting conflicts tenant-wide among policies with overlapping assignments."""
    if len(all_policies) < 2:
        return []

    group_to_policies: Dict[str, List[Policy]] = defaultdict(list)

    for policy in all_policies:
        group_ids = _get_assigned_group_ids(policy)
        if not group_ids:
            continue
        for gid in group_ids:
            group_to_policies[gid].append(policy)

    overlapping_sets: List[List[Policy]] = []
    for gid, policies in group_to_policies.items():
        if len(policies) >= 2:
            overlapping_sets.append(policies)

    seen_ids: Set[str] = set()
    overlapping_policies: List[Policy] = []
    for pset in overlapping_sets:
        for p in pset:
            if p.id not in seen_ids:
                seen_ids.add(p.id)
                overlapping_policies.append(p)

    if len(overlapping_policies) < 2:
        return []

    return _build_conflicts(overlapping_policies)


def build_conflict_stats(conflicts: List[ConflictItem]) -> Dict[str, Any]:
    """Compute summary stats from a list of conflict items."""
    affected_policy_ids: Set[str] = set()
    conflict_count = 0
    duplicate_count = 0

    for item in conflicts:
        for cp in item.policies:
            affected_policy_ids.add(cp.policy_id)
        if item.has_different_values:
            conflict_count += 1
        else:
            duplicate_count += 1

    return {
        "totalOverlapping": len(conflicts),
        "conflictCount": conflict_count,
        "matchingCount": duplicate_count,
        "affectedPolicies": len(affected_policy_ids),
    }
