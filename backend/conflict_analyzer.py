from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set

from models import ConflictItem, ConflictPolicy, Policy, PolicyType

logger = logging.getLogger(__name__)

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


def _make_setting_label(key: str) -> str:
    """Generate a human-readable label from a setting key."""
    # key format: policyType:path.to.setting
    parts = key.split(":", 1)
    if len(parts) == 2:
        return parts[1].replace(".", " › ").replace("_", " ")
    return key


# ── Setting extraction per policy type ───────────────────────────────────────


def _extract_raw_settings(
    policy: Policy, prefix: str
) -> List[Dict[str, Any]]:
    """Extract settings from the raw dict (Device Config, Compliance, etc.)."""
    results: List[Dict[str, Any]] = []
    raw = policy.raw
    for key, value in raw.items():
        if key.startswith("@") or key in _RAW_SKIP_FIELDS:
            continue
        setting_key = f"{prefix}:{key}"
        norm = _normalize_value(value)
        if norm is None:
            continue
        results.append({
            "setting_key": setting_key,
            "setting_label": _make_setting_label(setting_key),
            "value": norm,
            "policy_id": policy.id,
            "policy_name": policy.display_name,
            "policy_type": prefix,
        })
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

        # Extract value based on setting instance type
        value = _extract_setting_instance_value(instance, odata_type)

        setting_key = f"{prefix}:{definition_id}"
        norm = _normalize_value(value)
        results.append({
            "setting_key": setting_key,
            "setting_label": _make_setting_label(setting_key),
            "value": norm,
            "policy_id": policy.id,
            "policy_name": policy.display_name,
            "policy_type": prefix,
        })
    return results


def _extract_setting_instance_value(instance: dict[str, Any], odata_type: str) -> Any:
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
        value = setting.get("valueJson") or setting.get("value")
        # Try to parse valueJson
        if isinstance(value, str):
            import json

            try:
                value = json.loads(value)
            except (json.JSONDecodeError, ValueError):
                pass

        setting_key = f"{prefix}:{definition_id}"
        norm = _normalize_value(value)
        results.append({
            "setting_key": setting_key,
            "setting_label": _make_setting_label(setting_key),
            "value": norm,
            "policy_id": policy.id,
            "policy_name": policy.display_name,
            "policy_type": prefix,
        })
    return results


def _extract_group_policy_admx(policy: Policy) -> List[Dict[str, Any]]:
    """Extract settings from Group Policy (ADMX) configurations."""
    results: List[Dict[str, Any]] = []
    prefix = policy.policy_type.value
    for setting in policy.settings:
        def_id = setting.get("id", "")
        enabled = setting.get("enabled")
        definition = setting.get("definition", {})
        display_name = definition.get("displayName", def_id)

        setting_key = f"{prefix}:{def_id}"
        results.append({
            "setting_key": setting_key,
            "setting_label": display_name or _make_setting_label(setting_key),
            "value": _normalize_value(enabled),
            "policy_id": policy.id,
            "policy_name": policy.display_name,
            "policy_type": prefix,
        })
    return results


def _extract_conditional_access(policy: Policy) -> List[Dict[str, Any]]:
    """Extract settings from Conditional Access policies."""
    results: List[Dict[str, Any]] = []
    prefix = policy.policy_type.value
    raw = policy.raw

    conditions = raw.get("conditions", {})
    for cond_key, cond_val in conditions.items():
        setting_key = f"{prefix}:conditions.{cond_key}"
        norm = _normalize_value(cond_val)
        if norm is None:
            continue
        results.append({
            "setting_key": setting_key,
            "setting_label": _make_setting_label(setting_key),
            "value": norm,
            "policy_id": policy.id,
            "policy_name": policy.display_name,
            "policy_type": prefix,
        })

    grant_controls = raw.get("grantControls")
    if grant_controls:
        setting_key = f"{prefix}:grantControls"
        results.append({
            "setting_key": setting_key,
            "setting_label": _make_setting_label(setting_key),
            "value": _normalize_value(grant_controls),
            "policy_id": policy.id,
            "policy_name": policy.display_name,
            "policy_type": prefix,
        })

    session_controls = raw.get("sessionControls")
    if session_controls:
        setting_key = f"{prefix}:sessionControls"
        results.append({
            "setting_key": setting_key,
            "setting_label": _make_setting_label(setting_key),
            "value": _normalize_value(session_controls),
            "policy_id": policy.id,
            "policy_name": policy.display_name,
            "policy_type": prefix,
        })

    return results


def _extract_settings(policy: Policy) -> List[Dict[str, Any]]:
    """Extract normalized settings from any policy type."""
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
        # Sentinel to indicate "targets everyone"
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
    # If either targets all, they overlap
    if "__ALL__" in groups_a or "__ALL__" in groups_b:
        return True
    return bool(groups_a & groups_b)


# ── Conflict analysis ────────────────────────────────────────────────────────


def _build_conflicts(
    policies: List[Policy],
) -> List[ConflictItem]:
    """Given a list of policies, find shared settings and classify conflicts vs duplicates."""
    # setting_key -> list of extracted setting dicts
    settings_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for policy in policies:
        extracted = _extract_settings(policy)
        for s in extracted:
            settings_map[s["setting_key"]].append(s)

    conflicts: List[ConflictItem] = []

    for setting_key, entries in settings_map.items():
        if len(entries) < 2:
            continue

        # De-duplicate by policy_id (same policy shouldn't conflict with itself)
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
            )
            for entry in unique_entries
        ]

        # Use label from first entry
        label = unique_entries[0].get("setting_label", "")

        conflicts.append(
            ConflictItem(
                setting_key=setting_key,
                setting_label=label,
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
    """Find setting conflicts among policies targeting a specific group.

    ``group_policy_mappings`` is the resolved list of GroupPolicyMapping dicts
    that contain the policies applying to *group_id*.  We flatten all policies
    from the mappings and analyse them.
    """
    # Collect all policy IDs that target this group
    policy_ids: Set[str] = set()
    for mapping in group_policy_mappings:
        policies_in_mapping = mapping.get("policies", [])
        for p in policies_in_mapping:
            pid = p.get("id") or (p.id if isinstance(p, Policy) else "")
            if pid:
                policy_ids.add(pid)

    # Filter all_policies to only those targeting this group
    targeted = [p for p in all_policies if p.id in policy_ids]

    if len(targeted) < 2:
        return []

    return _build_conflicts(targeted)


def analyze_all_conflicts(all_policies: List[Policy]) -> List[ConflictItem]:
    """Find setting conflicts tenant-wide among policies with overlapping assignments."""
    if len(all_policies) < 2:
        return []

    # Build overlap groups: for each pair of policies that overlap, combine
    # their settings.  To avoid O(n²) on the full list, group by assignment
    # target first.

    # group_id -> list of policies
    group_to_policies: Dict[str, List[Policy]] = defaultdict(list)

    for policy in all_policies:
        group_ids = _get_assigned_group_ids(policy)
        if not group_ids:
            continue
        for gid in group_ids:
            group_to_policies[gid].append(policy)

    # Collect all policies that share at least one assignment target
    overlapping_sets: List[List[Policy]] = []
    for gid, policies in group_to_policies.items():
        if len(policies) >= 2:
            overlapping_sets.append(policies)

    # Merge into a single de-duplicated list of policies that overlap with
    # at least one other policy
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
        "totalSharedSettings": len(conflicts),
        "conflictCount": conflict_count,
        "duplicateCount": duplicate_count,
        "affectedPolicies": len(affected_policy_ids),
    }
