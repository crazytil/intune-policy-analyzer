from __future__ import annotations

import logging
from typing import Any, Optional

from graph_client import GraphClient
from models import (
    AssignmentSource,
    Group,
    GroupPolicyMapping,
    Policy,
)

logger = logging.getLogger(__name__)

# Well-known Graph assignment target types
_ALL_USERS_TYPE = "#microsoft.graph.allLicensedUsersAssignmentTarget"
_ALL_DEVICES_TYPE = "#microsoft.graph.allDevicesAssignmentTarget"
_GROUP_INCLUDE_TYPE = "#microsoft.graph.groupAssignmentTarget"
_GROUP_EXCLUDE_TYPE = "#microsoft.graph.exclusionGroupAssignmentTarget"


def _build_group(raw: dict[str, Any]) -> Group:
    return Group(
        id=raw.get("id", ""),
        display_name=raw.get("displayName", ""),
        description=raw.get("description"),
        member_count=raw.get("memberCount"),
        group_types=raw.get("groupTypes", []),
        membership_rule=raw.get("membershipRule"),
    )


async def search_groups(client: GraphClient, query: str) -> list[Group]:
    """Search groups by display name using $filter startsWith."""
    try:
        params = {
            "$filter": f"startsWith(displayName, '{query}')",
            "$top": "25",
            "$orderby": "displayName",
            "$count": "true",
        }
        # ConsistencyLevel header is needed for $count and advanced filters
        raw_groups = await client.get("groups", params=params)
        return [_build_group(g) for g in raw_groups]
    except Exception:
        # Fallback: try $search if $filter fails (some tenants require it)
        try:
            params = {
                "$search": f'"displayName:{query}"',
                "$top": "25",
                "$count": "true",
            }
            raw_groups = await client.get("groups", params=params)
            return [_build_group(g) for g in raw_groups]
        except Exception as e:
            logger.error("Failed to search groups: %s", e)
            return []


async def get_group(client: GraphClient, group_id: str) -> Optional[Group]:
    """Get a single group by ID."""
    try:
        raw = await client.get_single(f"groups/{group_id}")
        return _build_group(raw)
    except Exception as e:
        logger.error("Failed to get group %s: %s", group_id, e)
        return None


async def get_group_transitive_members(
    client: GraphClient, group_id: str
) -> list[dict[str, Any]]:
    """Get all transitive members of a group (for member count)."""
    try:
        return await client.get(
            f"groups/{group_id}/transitiveMembers",
            params={"$select": "id,displayName,userPrincipalName", "$top": "999"},
        )
    except Exception as e:
        logger.error("Failed to get transitive members for %s: %s", group_id, e)
        return []


async def get_group_transitive_member_of(
    client: GraphClient, group_id: str
) -> list[dict[str, Any]]:
    """Get all groups this group is a transitive member of (parent groups)."""
    try:
        results = await client.get(
            f"groups/{group_id}/transitiveMemberOf",
            params={"$select": "id,displayName,groupTypes,membershipRule"},
        )
        # Filter to only groups (not roles, etc.)
        return [
            r for r in results
            if r.get("@odata.type", "") == "#microsoft.graph.group"
        ]
    except Exception as e:
        logger.error("Failed to get transitive memberOf for %s: %s", group_id, e)
        return []


def _get_target_group_ids(policy: Policy) -> dict[str, str]:
    """Extract group IDs and their assignment type from a policy's assignments.

    Returns dict mapping group_id -> 'include' or 'exclude'.
    """
    result: dict[str, str] = {}
    for assignment in policy.assignments:
        target = assignment.get("target", {})
        odata_type = target.get("@odata.type", "")
        group_id = target.get("groupId", "")

        if odata_type == _GROUP_INCLUDE_TYPE and group_id:
            result[group_id] = "include"
        elif odata_type == _GROUP_EXCLUDE_TYPE and group_id:
            result[group_id] = "exclude"
    return result


def _has_all_users_assignment(policy: Policy) -> bool:
    for assignment in policy.assignments:
        target = assignment.get("target", {})
        odata_type = target.get("@odata.type", "")
        if odata_type == _ALL_USERS_TYPE:
            return True
        # Conditional Access "All" users
        if target.get("assignmentType") == "include" and odata_type == _ALL_USERS_TYPE:
            return True
    return False


def _has_all_devices_assignment(policy: Policy) -> bool:
    for assignment in policy.assignments:
        target = assignment.get("target", {})
        if target.get("@odata.type", "") == _ALL_DEVICES_TYPE:
            return True
    return False


async def resolve_policies_for_group(
    client: GraphClient, group_id: str, all_policies: list[Policy]
) -> list[GroupPolicyMapping]:
    """Find all policies that apply to a group, with assignment source tracking."""
    group = await get_group(client, group_id)
    if not group:
        return []

    # Get all parent groups for inheritance resolution
    parent_groups_raw = await get_group_transitive_member_of(client, group_id)
    parent_group_ids = {g["id"] for g in parent_groups_raw}

    direct_policies: list[Policy] = []
    inherited_policies: list[Policy] = []
    all_users_policies: list[Policy] = []
    all_devices_policies: list[Policy] = []

    for policy in all_policies:
        target_groups = _get_target_group_ids(policy)

        # Check for exclusion first — if this group is excluded, skip
        if target_groups.get(group_id) == "exclude":
            continue

        # Direct assignment
        if target_groups.get(group_id) == "include":
            direct_policies.append(policy)
        # Inherited via parent group
        elif parent_group_ids & set(target_groups.keys()):
            # Only if at least one parent is an include
            inherited_parents = parent_group_ids & {
                gid for gid, atype in target_groups.items() if atype == "include"
            }
            if inherited_parents:
                inherited_policies.append(policy)

        # All Users / All Devices
        if _has_all_users_assignment(policy):
            if policy not in direct_policies and policy not in inherited_policies:
                all_users_policies.append(policy)
        if _has_all_devices_assignment(policy):
            if (
                policy not in direct_policies
                and policy not in inherited_policies
                and policy not in all_users_policies
            ):
                all_devices_policies.append(policy)

    mappings: list[GroupPolicyMapping] = []

    if direct_policies:
        mappings.append(
            GroupPolicyMapping(
                group=group,
                policies=direct_policies,
                assignment_source=AssignmentSource.DIRECT,
            )
        )
    if inherited_policies:
        mappings.append(
            GroupPolicyMapping(
                group=group,
                policies=inherited_policies,
                assignment_source=AssignmentSource.INHERITED,
            )
        )
    if all_users_policies:
        mappings.append(
            GroupPolicyMapping(
                group=group,
                policies=all_users_policies,
                assignment_source=AssignmentSource.ALL_USERS,
            )
        )
    if all_devices_policies:
        mappings.append(
            GroupPolicyMapping(
                group=group,
                policies=all_devices_policies,
                assignment_source=AssignmentSource.ALL_DEVICES,
            )
        )

    return mappings


def resolve_groups_for_policy(
    policy: Policy,
) -> list[dict[str, Any]]:
    """Extract all group targets from a policy's assignments with include/exclude type."""
    groups: list[dict[str, Any]] = []

    for assignment in policy.assignments:
        target = assignment.get("target", {})
        odata_type = target.get("@odata.type", "")
        group_id = target.get("groupId", "")

        if odata_type == _GROUP_INCLUDE_TYPE and group_id:
            groups.append({
                "group_id": group_id,
                "assignment_type": "include",
                "filter_id": target.get("deviceAndAppManagementAssignmentFilterId"),
                "filter_type": target.get("deviceAndAppManagementAssignmentFilterType"),
            })
        elif odata_type == _GROUP_EXCLUDE_TYPE and group_id:
            groups.append({
                "group_id": group_id,
                "assignment_type": "exclude",
                "filter_id": target.get("deviceAndAppManagementAssignmentFilterId"),
                "filter_type": target.get("deviceAndAppManagementAssignmentFilterType"),
            })
        elif odata_type == _ALL_USERS_TYPE:
            groups.append({
                "group_id": None,
                "assignment_type": "all_users",
                "filter_id": None,
                "filter_type": None,
            })
        elif odata_type == _ALL_DEVICES_TYPE:
            groups.append({
                "group_id": None,
                "assignment_type": "all_devices",
                "filter_id": None,
                "filter_type": None,
            })

    return groups
