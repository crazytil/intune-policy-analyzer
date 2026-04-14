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

_SETTINGS_CATALOG_PREFIX_MAP: Dict[str, str] = {
    "device_vendor_msft_policy_config": "Settings Catalog",
    "device_vendor_msft_defender": "Settings Catalog",
}

_SETTINGS_SEGMENT_LABELS: Dict[str, str] = {
    "msft": "Microsoft",
    "config": "Configuration",
    "defender": "Defender",
    "bitlocker": "BitLocker",
    "firewall": "Firewall",
    "browser": "Browser",
}

_SETTINGS_LEAF_LABELS: Dict[str, str] = {
    "allowarchivescanning": "Allow Archive Scanning",
    "allowfullscanremovabledrivescanning": "Allow Full Scan Removable Drives Scanning",
    "submitsamplesconsent": "Submit Samples Consent",
}

_SETTINGS_ENUM_VALUE_MAP: Dict[str, Dict[str, str]] = {}

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

_SCRIPT_POLICY_TYPES: Set[PolicyType] = {
    PolicyType.POWERSHELL_SCRIPTS,
    PolicyType.REMEDIATION_SCRIPTS,
}

_DEVICE_CONFIGURATION_METADATA_FIELDS: Set[str] = {
    "certFileName",
    "destinationStore",
    "trustedRootCertificate",
    "renewalThresholdPercentage",
    "subjectNameFormatString",
    "subjectAlternativeNameType",
    "certificateAccessType",
    "certificateStore",
    "certificateValidityPeriodScale",
    "certificateValidityPeriodValue",
    "customSubjectAlternativeNames",
    "intendedPurpose",
    "keySize",
    "keyStorageProvider",
    "rootCertificateName",
}

_CERTIFICATE_ODATA_MARKERS = (
    "certificate",
    "pkcs",
    "scep",
    "derivedcredential",
)

_RAW_PROFILE_SKIP_MARKERS = (
    "wifi",
    "wi-fi",
    "wireless",
    "customconfiguration",
    "omaconfiguration",
)

_RAW_SCHEMA_FALSEY_DEFAULT_SKIP = {
    "windows10GeneralConfiguration",
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


def _snake_to_title(name: str) -> str:
    compact = name.replace("_", "").lower()
    if compact in _SETTINGS_LEAF_LABELS:
        return _SETTINGS_LEAF_LABELS[compact]

    normalized = _camel_to_title(name.replace("_", " "))
    parts = normalized.split()
    return " ".join(
        _SETTINGS_SEGMENT_LABELS.get(part.lower(), part.upper() if len(part) <= 3 else part)
        for part in parts
        if part
    )


def _format_value_path(setting_key: str) -> str:
    if ":" not in setting_key:
        return setting_key

    prefix, raw_path = setting_key.split(":", 1)
    if prefix != PolicyType.SETTINGS_CATALOG.value:
        return setting_key.replace(":", " > ")

    for known_prefix, display_prefix in _SETTINGS_CATALOG_PREFIX_MAP.items():
        if raw_path.startswith(known_prefix + "_"):
            remainder = raw_path[len(known_prefix) + 1:]
            category, _, leaf_raw = remainder.partition("_")
            leaf = _snake_to_title(leaf_raw or category)
            return f"{display_prefix} > {_snake_to_title(category)} > {leaf}"

    return f"Settings Catalog > {_snake_to_title(raw_path)}"


def _decode_settings_catalog_value(value: str) -> Optional[str]:
    for definition_id, value_map in _SETTINGS_ENUM_VALUE_MAP.items():
        marker = f"{definition_id}_"
        if value.startswith(marker):
            code = value[len(marker):]
            if code in value_map:
                return value_map[code]

    match = re.match(r"(.+)_([0-9]+)$", value)
    if not match:
        return None

    definition_id, code = match.groups()
    leaf_name = definition_id.rsplit("_", 1)[-1]
    if code == "1" and leaf_name.startswith(("allow", "enable", "require")):
        return "Enabled"
    if code == "0" and leaf_name.startswith(("allow", "enable", "require")):
        return "Disabled"
    return f"{_snake_to_title(leaf_name)}: Option {code}"


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
        if low in ("notconfigured", "userdefined", "devicedefault"):
            return "Not Configured"
        if value == "0001-01-01T00:00:00Z":
            return "Not Configured"
        decoded = _decode_settings_catalog_value(value)
        if decoded:
            return decoded
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
        if low in ("notconfigured", "userdefined", "devicedefault"):
            return None
        if value == "0001-01-01T00:00:00Z":
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
        "platform_key": _platform_bucket_key(policy),
    }


def _extract_raw_settings(policy: Policy, prefix: str) -> List[Dict[str, Any]]:
    """Extract settings from the raw dict (Device Config, Compliance, etc.)."""
    results: List[Dict[str, Any]] = []
    raw = policy.raw
    if _should_skip_raw_policy(policy):
        return results
    raw_schema = _raw_policy_schema_key(policy)
    for key, value in raw.items():
        if key.startswith("@") or key in _RAW_SKIP_FIELDS or _should_skip_raw_setting(policy, key):
            continue
        norm = _normalize_value(value)
        if norm is None:
            continue
        if raw_schema in _RAW_SCHEMA_FALSEY_DEFAULT_SKIP and norm is False:
            continue
        setting_key = (
            f"{prefix}:{raw_schema}|{key}"
            if raw_schema
            else f"{prefix}:{key}"
        )
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

        definition = _get_matching_definition(setting, definition_id)

        # Try to get friendly name from embedded settingDefinitions
        display_name = _resolve_catalog_display_name(setting, definition_id)

        # Extract value based on setting instance type
        value = _extract_setting_instance_value(instance, odata_type)

        setting_key = _resolve_catalog_setting_key(setting, definition_id, prefix)
        entry = _make_entry(setting_key, display_name, value, policy, prefix)
        resolved_value_display = _resolve_catalog_value_display(
            setting,
            definition,
            instance,
            value,
        )
        if resolved_value_display:
            entry["value_display"] = resolved_value_display
        results.append(entry)
    return results


def _resolve_catalog_display_name(
    setting: Dict[str, Any], definition_id: str
) -> str:
    """Get the display name from settingDefinitions if available."""
    definition = _get_matching_definition(setting, definition_id)
    if definition:
        name = definition.get("displayName", "")
        if name:
            return name

    # Fallback: extract a readable name from the definition ID
    # Format: device_vendor_msft_policy_config_<category>_<setting>
    parts = definition_id.rsplit("_", 1)
    if len(parts) > 1:
        return _camel_to_title(parts[-1])
    return definition_id


def _get_matching_definition(
    setting: Dict[str, Any], definition_id: str
) -> Optional[Dict[str, Any]]:
    definitions = setting.get("settingDefinitions", [])
    for definition in definitions:
        if definition.get("id", "") == definition_id:
            return definition
    if definitions:
        return definitions[0]
    return None


def _resolve_catalog_setting_key(
    setting: Dict[str, Any], definition_id: str, prefix: str
) -> str:
    definition = _get_matching_definition(setting, definition_id)
    if definition:
        base_uri = str(definition.get("baseUri") or "").strip()
        offset_uri = str(definition.get("offsetUri") or "").strip()
        if base_uri or offset_uri:
            path_parts = [part.strip("/") for part in (base_uri, offset_uri) if part]
            if path_parts:
                return f"{prefix}:{'/'.join(path_parts)}"
    return f"{prefix}:{definition_id}"


def _resolve_catalog_value_display(
    setting: Dict[str, Any],
    definition: Optional[Dict[str, Any]],
    instance: Dict[str, Any],
    value: Any,
) -> Optional[str]:
    type_lower = str(instance.get("@odata.type", "")).lower()
    if "choicesettinginstance" in type_lower and isinstance(value, str):
        if definition:
            choice_display = _resolve_choice_value_display(definition, value)
            if choice_display:
                return choice_display
        return _decode_settings_catalog_value(value)

    if "groupsettinginstance" in type_lower or "groupsettingcollectioninstance" in type_lower:
        if "groupsettingcollectioninstance" in type_lower:
            collections = instance.get("groupSettingCollectionValue", [])
            children = [
                child
                for collection in collections
                for child in collection.get("children", [])
            ]
        else:
            children = instance.get("groupSettingValue", {}).get("children", [])
        rendered_children: List[str] = []
        for child in children:
            child_definition_id = child.get("settingDefinitionId", "")
            child_definition = _get_matching_definition(setting, child_definition_id)
            child_label = (
                child_definition.get("displayName")
                if child_definition
                else _friendly_name_for_catalog_id(child_definition_id)
            )
            child_value = _extract_setting_instance_value(
                child, child.get("@odata.type", "")
            )
            child_display = _resolve_catalog_value_display(
                setting,
                child_definition,
                child,
                child_value,
            ) or _format_value_display(child_value)
            rendered_children.append(f"{child_label}: {child_display}")
        if rendered_children:
            return "\n".join(rendered_children)

    return None


def _resolve_choice_value_display(
    definition: Dict[str, Any], selected_value: str
) -> Optional[str]:
    options = definition.get("options", [])
    for option in options:
        display_name = option.get("displayName") or option.get("name")
        if not display_name:
            continue

        if option.get("itemId") == selected_value:
            return display_name

        option_value = option.get("optionValue", {})
        if _option_value_matches(option_value, selected_value):
            return display_name

    return None


def _option_value_matches(option_value: Dict[str, Any], selected_value: str) -> bool:
    if option_value.get("value") == selected_value:
        return True

    choice_value = option_value.get("choiceSettingValue", {})
    if isinstance(choice_value, dict) and choice_value.get("value") == selected_value:
        return True

    for child in option_value.get("children", []):
        child_choice = child.get("choiceSettingValue", {})
        if isinstance(child_choice, dict) and child_choice.get("value") == selected_value:
            return True

    return False


def _friendly_name_for_catalog_id(definition_id: str) -> str:
    leaf = definition_id.rsplit("_", 1)[-1]
    return _snake_to_title(leaf)


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
    if "groupsettingcollectioninstance" in type_lower:
        return instance.get("groupSettingCollectionValue", [])
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

        if ptype in _SCRIPT_POLICY_TYPES:
            return []

        if ptype in (
            PolicyType.APP_PROTECTION,
            PolicyType.APP_CONFIGURATION,
            PolicyType.AUTOPILOT,
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


def _normalize_platform_token(token: str) -> Optional[str]:
    low = token.strip().lower()
    if not low:
        return None
    if "windows" in low:
        return "windows"
    if "ios" in low or "iphone" in low or "ipad" in low:
        return "ios"
    if "macos" in low or low == "mac" or "mac " in low:
        return "macos"
    if "android" in low:
        return "android"
    if "linux" in low:
        return "linux"
    if "all" in low or "any" in low:
        return "all"
    if "unknown" in low:
        return "unknown"
    return low


def _platform_tokens(policy: Policy) -> Set[str]:
    raw_platform = (policy.platform or "").strip()
    if not raw_platform:
        return {"unknown"}

    tokens = {
        normalized
        for part in re.split(r"[,/|]+", raw_platform)
        for normalized in [_normalize_platform_token(part)]
        if normalized
    }
    return tokens or {"unknown"}


def _platform_bucket_key(policy: Policy) -> str:
    return "|".join(sorted(_platform_tokens(policy)))


def _policy_matches_platform_filter(policy: Policy, selected_platforms: Optional[Set[str]]) -> bool:
    if not selected_platforms:
        return True
    policy_platforms = _platform_tokens(policy)
    if "all" in policy_platforms:
        return True
    return bool(policy_platforms & selected_platforms)


def _filter_policies_by_platforms(
    policies: List[Policy], selected_platforms: Optional[Set[str]]
) -> List[Policy]:
    if not selected_platforms:
        return policies
    return [policy for policy in policies if _policy_matches_platform_filter(policy, selected_platforms)]


def _should_skip_raw_policy(policy: Policy) -> bool:
    if policy.policy_type != PolicyType.DEVICE_CONFIGURATION:
        return False
    odata_type = str(policy.raw.get("@odata.type", "")).lower()
    return any(marker in odata_type for marker in _CERTIFICATE_ODATA_MARKERS + _RAW_PROFILE_SKIP_MARKERS)


def _should_skip_raw_setting(policy: Policy, key: str) -> bool:
    if policy.policy_type == PolicyType.DEVICE_CONFIGURATION and key in _DEVICE_CONFIGURATION_METADATA_FIELDS:
        return True
    return False


def _raw_policy_schema_key(policy: Policy) -> str:
    odata_type = str(policy.raw.get("@odata.type", "")).strip()
    if not odata_type:
        return ""
    return odata_type.removeprefix("#microsoft.graph.")


def _is_default_like_value(value: Any) -> bool:
    if value in (None, False, 0, ""):
        return True
    if isinstance(value, (list, dict)):
        return len(value) == 0
    return False


def _should_skip_matching_entries(entries: List[Dict[str, Any]]) -> bool:
    if not entries:
        return False
    if any(entry["policy_type"] != PolicyType.DEVICE_CONFIGURATION.value for entry in entries):
        return False
    return all(_is_default_like_value(entry["value"]) for entry in entries)


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

        platform_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for entry in entries:
            platform_groups[entry.get("platform_key", "unknown")].append(entry)

        for unique_entries in platform_groups.values():
            if len(unique_entries) < 2:
                continue

            # De-duplicate by policy_id
            seen_policy_ids: Set[str] = set()
            deduped_entries: List[Dict[str, Any]] = []
            for entry in unique_entries:
                if entry["policy_id"] not in seen_policy_ids:
                    seen_policy_ids.add(entry["policy_id"])
                    deduped_entries.append(entry)

            if len(deduped_entries) < 2:
                continue

            # Check if values differ
            values = [entry["value"] for entry in deduped_entries]
            has_different = len(set(repr(v) for v in values)) > 1
            if not has_different and _should_skip_matching_entries(deduped_entries):
                continue

            conflict_policies = [
                ConflictPolicy(
                    policy_id=entry["policy_id"],
                    policy_name=entry["policy_name"],
                    policy_type=entry["policy_type"],
                    value=entry["value"],
                    value_display=entry.get("value_display", ""),
                )
                for entry in deduped_entries
            ]

            # Use display_name from first entry
            display_name = deduped_entries[0].get("display_name", "")

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
    selected_platforms: Optional[Set[str]] = None,
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
    targeted = _filter_policies_by_platforms(targeted, selected_platforms)

    if len(targeted) < 2:
        return []

    return _build_conflicts(targeted)


def analyze_conflicts_for_target(
    target: str, all_policies: List[Policy], selected_platforms: Optional[Set[str]] = None
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

    targeted = _filter_policies_by_platforms(targeted, selected_platforms)

    if len(targeted) < 2:
        return []

    return _build_conflicts(targeted)


def analyze_conflicts_for_policy(
    policy_id: str, all_policies: List[Policy], selected_platforms: Optional[Set[str]] = None
) -> List[ConflictItem]:
    """Find setting conflicts for a specific policy against all others."""
    target_policy = None
    for p in all_policies:
        if p.id == policy_id:
            target_policy = p
            break
    if not target_policy:
        return []
    if not _policy_matches_platform_filter(target_policy, selected_platforms):
        return []

    target_groups = _get_assigned_group_ids(target_policy)

    # Find all policies that share at least one assignment group with the target
    related_policies = [target_policy]
    for p in all_policies:
        if p.id == policy_id:
            continue
        p_groups = _get_assigned_group_ids(p)
        if target_groups & p_groups and _policy_matches_platform_filter(p, selected_platforms):
            related_policies.append(p)

    if len(related_policies) < 2:
        return []

    # Build conflicts but only return items where the target policy is involved
    all_conflicts = _build_conflicts(related_policies)
    return [
        c for c in all_conflicts
        if any(cp.policy_id == policy_id for cp in c.policies)
    ]


def analyze_all_conflicts(
    all_policies: List[Policy], selected_platforms: Optional[Set[str]] = None
) -> List[ConflictItem]:
    """Find setting conflicts tenant-wide among policies with overlapping assignments."""
    all_policies = _filter_policies_by_platforms(all_policies, selected_platforms)
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
