from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from graph_client import GraphClient
from models import Policy, PolicyType

logger = logging.getLogger(__name__)

# Maps PolicyType to (Graph endpoint, has separate assignments endpoint, settings sub-endpoint or None)
POLICY_ENDPOINTS: dict[PolicyType, dict[str, Any]] = {
    PolicyType.DEVICE_CONFIGURATION: {
        "endpoint": "deviceManagement/deviceConfigurations",
        "has_assignments": True,
        "settings_endpoint": None,
    },
    PolicyType.SETTINGS_CATALOG: {
        "endpoint": "deviceManagement/configurationPolicies",
        "has_assignments": True,
        "settings_endpoint": "settings",
    },
    PolicyType.COMPLIANCE: {
        "endpoint": "deviceManagement/deviceCompliancePolicies",
        "has_assignments": True,
        "settings_endpoint": None,
    },
    PolicyType.COMPLIANCE_V2: {
        "endpoint": "deviceManagement/compliancePolicies",
        "has_assignments": True,
        "settings_endpoint": "settings",
    },
    PolicyType.APP_PROTECTION: {
        "endpoint": "deviceManagement/managedAppPolicies",
        "has_assignments": True,
        "settings_endpoint": None,
    },
    PolicyType.APP_CONFIGURATION: {
        "endpoint": "deviceAppManagement/mobileAppConfigurations",
        "has_assignments": True,
        "settings_endpoint": None,
    },
    PolicyType.ENDPOINT_SECURITY: {
        "endpoint": "deviceManagement/intents",
        "has_assignments": True,
        "settings_endpoint": "categories",
    },
    PolicyType.CONDITIONAL_ACCESS: {
        "endpoint": "identity/conditionalAccessPolicies",
        "has_assignments": False,  # Inline conditions
        "settings_endpoint": None,
    },
    PolicyType.AUTOPILOT: {
        "endpoint": "deviceManagement/windowsAutopilotDeploymentProfiles",
        "has_assignments": True,
        "settings_endpoint": None,
    },
    PolicyType.POWERSHELL_SCRIPTS: {
        "endpoint": "deviceManagement/deviceManagementScripts",
        "has_assignments": True,
        "settings_endpoint": None,
    },
    PolicyType.REMEDIATION_SCRIPTS: {
        "endpoint": "deviceManagement/deviceHealthScripts",
        "has_assignments": True,
        "settings_endpoint": None,
    },
    PolicyType.GROUP_POLICY_ADMX: {
        "endpoint": "deviceManagement/groupPolicyConfigurations",
        "has_assignments": True,
        "settings_endpoint": "definitionValues",
    },
}


async def _fetch_assignments(
    client: GraphClient, endpoint: str, policy_id: str
) -> list[dict[str, Any]]:
    try:
        return await client.get(f"{endpoint}/{policy_id}/assignments")
    except Exception as e:
        logger.warning("Failed to fetch assignments for %s: %s", policy_id, e)
        return []


async def _fetch_settings(
    client: GraphClient,
    endpoint: str,
    policy_id: str,
    policy_type: PolicyType,
    settings_endpoint: str,
) -> list[dict[str, Any]]:
    try:
        if policy_type == PolicyType.ENDPOINT_SECURITY:
            # Endpoint Security: fetch categories, then settings per category
            categories = await client.get(
                f"{endpoint}/{policy_id}/categories"
            )
            all_settings: list[dict[str, Any]] = []
            for category in categories:
                cat_id = category.get("id", "")
                cat_settings = await client.get(
                    f"{endpoint}/{policy_id}/categories/{cat_id}/settings"
                )
                for s in cat_settings:
                    s["_categoryId"] = cat_id
                    s["_categoryDisplayName"] = category.get("displayName", "")
                all_settings.extend(cat_settings)
            return all_settings
        elif policy_type in (PolicyType.SETTINGS_CATALOG, PolicyType.COMPLIANCE_V2):
            return await client.get(
                f"{endpoint}/{policy_id}/{settings_endpoint}",
                params={"$expand": "settingDefinitions"},
            )
        else:
            return await client.get(
                f"{endpoint}/{policy_id}/{settings_endpoint}"
            )
    except Exception as e:
        logger.warning(
            "Failed to fetch settings for %s (%s): %s", policy_id, policy_type, e
        )
        return []


def _extract_conditional_access_assignments(
    raw: dict[str, Any],
) -> list[dict[str, Any]]:
    """Extract assignment-like structures from Conditional Access inline conditions."""
    assignments: list[dict[str, Any]] = []
    conditions = raw.get("conditions", {})

    users = conditions.get("users", {})
    # Include groups
    for group_id in users.get("includeGroups", []):
        assignments.append(
            {
                "target": {
                    "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                    "groupId": group_id,
                    "assignmentType": "include",
                }
            }
        )
    # Exclude groups
    for group_id in users.get("excludeGroups", []):
        assignments.append(
            {
                "target": {
                    "@odata.type": "#microsoft.graph.exclusionGroupAssignmentTarget",
                    "groupId": group_id,
                    "assignmentType": "exclude",
                }
            }
        )
    # All users
    if "All" in users.get("includeUsers", []):
        assignments.append(
            {
                "target": {
                    "@odata.type": "#microsoft.graph.allLicensedUsersAssignmentTarget",
                    "assignmentType": "include",
                }
            }
        )
    return assignments


def _build_policy(
    raw: dict[str, Any],
    policy_type: PolicyType,
    assignments: list[dict[str, Any]],
    extra_settings: list[dict[str, Any]],
) -> Policy:
    return Policy(
        id=raw.get("id", ""),
        display_name=raw.get("displayName") or raw.get("name") or "",
        description=raw.get("description"),
        policy_type=policy_type,
        platform=_detect_platform(raw, policy_type),
        created=raw.get("createdDateTime"),
        modified=raw.get("lastModifiedDateTime"),
        settings=extra_settings,
        assignments=assignments,
        raw=raw,
    )


def _detect_platform(raw: dict[str, Any], policy_type: PolicyType) -> Optional[str]:
    # Try common platform fields
    for key in ("platformType", "platforms", "platform"):
        val = raw.get(key)
        if val:
            if isinstance(val, list):
                return ", ".join(str(v) for v in val)
            return str(val)

    # Infer from @odata.type
    odata_type = raw.get("@odata.type", "").lower()
    if "windows" in odata_type:
        return "windows"
    if "ios" in odata_type or "iphone" in odata_type:
        return "iOS"
    if "macos" in odata_type or "mac" in odata_type:
        return "macOS"
    if "android" in odata_type:
        return "android"

    return None


async def _fetch_policy_type(
    client: GraphClient, policy_type: PolicyType
) -> list[Policy]:
    config = POLICY_ENDPOINTS[policy_type]
    endpoint = config["endpoint"]

    try:
        raw_policies = await client.get(endpoint)
    except Exception as e:
        logger.error("Failed to fetch %s: %s", policy_type.value, e)
        return []

    policies: list[Policy] = []

    for raw in raw_policies:
        policy_id = raw.get("id", "")

        # Fetch assignments
        if config["has_assignments"]:
            assignments = await _fetch_assignments(client, endpoint, policy_id)
        else:
            # Conditional Access — extract from inline conditions
            assignments = _extract_conditional_access_assignments(raw)

        # Fetch additional settings if needed
        extra_settings: list[dict[str, Any]] = []
        if config["settings_endpoint"]:
            extra_settings = await _fetch_settings(
                client, endpoint, policy_id, policy_type, config["settings_endpoint"]
            )

        policies.append(
            _build_policy(raw, policy_type, assignments, extra_settings)
        )

    logger.info("Fetched %d %s policies", len(policies), policy_type.value)
    return policies


async def fetch_all_policies(client: GraphClient) -> list[Policy]:
    """Fetch all 12 policy types in parallel, return combined list."""
    tasks = [
        _fetch_policy_type(client, policy_type)
        for policy_type in POLICY_ENDPOINTS
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_policies: list[Policy] = []
    for policy_type, result in zip(POLICY_ENDPOINTS, results):
        if isinstance(result, Exception):
            logger.error(
                "Exception fetching %s: %s", policy_type.value, result
            )
            continue
        all_policies.extend(result)

    logger.info("Total policies fetched: %d", len(all_policies))
    return all_policies
