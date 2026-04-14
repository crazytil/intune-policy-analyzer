from __future__ import annotations

import logging
import time
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

import auth
from cache_utils import AsyncSingleFlight, TTLCache
from config import settings
from graph_client import GraphClient
from group_resolver import (
    clear_group_caches,
    get_group,
    get_group_transitive_members,
    resolve_groups_for_policy,
    resolve_policies_for_group,
    search_groups,
)
from conflict_analyzer import analyze_all_conflicts, analyze_conflicts_for_group, analyze_conflicts_for_policy, analyze_conflicts_for_target, build_conflict_stats
from models import AuthStatus, GroupPolicyMapping, Policy
from policy_fetcher import fetch_all_policies

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Intune Policy Analyzer", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory cache
_policies_cache: dict[str, Policy] = {}
_policy_cache_expires_at: float = 0.0
_policy_list_cache: list[Policy] = []
_policy_fetch_singleflight: AsyncSingleFlight[str, list[Policy]] = AsyncSingleFlight()
_groups_cache: TTLCache[str, list[dict[str, Any]]] = TTLCache(
    ttl_seconds=settings.groups_cache_ttl_seconds,
    max_entries=8,
)
_graph_client: Optional[GraphClient] = None


def _get_graph_client() -> GraphClient:
    global _graph_client
    if _graph_client is None:
        _graph_client = GraphClient()
    return _graph_client


def _normalize_platform_filters(platforms: Optional[list[str]]) -> Optional[set[str]]:
    if not platforms:
        return None
    normalized = {platform.strip().lower() for platform in platforms if platform.strip()}
    return normalized or None


def _set_policies_cache(policies: list[Policy]) -> None:
    global _policy_cache_expires_at, _policy_list_cache
    _policies_cache.clear()
    for policy in policies:
        _policies_cache[policy.id] = policy
    _policy_list_cache = list(policies)
    _policy_cache_expires_at = time.monotonic() + settings.policies_cache_ttl_seconds


def _get_cached_policies() -> Optional[list[Policy]]:
    if _policy_list_cache and time.monotonic() < _policy_cache_expires_at:
        return list(_policy_list_cache)
    return None


async def _ensure_policies_loaded() -> None:
    if _get_cached_policies() is None:
        await _load_policies()


async def _load_policies(force_refresh: bool = False) -> list[Policy]:
    cached = None if force_refresh else _get_cached_policies()
    if cached is not None:
        return cached

    client = _get_graph_client()

    async def fetch() -> list[Policy]:
        policies = await fetch_all_policies(client)
        _set_policies_cache(policies)
        return list(policies)

    return await _policy_fetch_singleflight.run("policies", fetch)


# ── Auth routes ──────────────────────────────────────────────────────────────


@app.get("/api/auth/status", response_model=AuthStatus, response_model_by_alias=True)
async def auth_status() -> AuthStatus:
    return auth.get_auth_status()


@app.post("/api/auth/login", response_model=AuthStatus, response_model_by_alias=True)
async def auth_login() -> AuthStatus:
    global _policy_cache_expires_at, _policy_list_cache
    try:
        status = auth.initiate_auth()
        _policies_cache.clear()
        _policy_list_cache = []
        _policy_cache_expires_at = 0.0
        _groups_cache.clear()
        clear_group_caches()
        return status
    except Exception as e:
        logger.error("Login failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Login failed: {e}")


@app.post("/api/auth/logout")
async def auth_logout() -> dict[str, str]:
    global _policy_cache_expires_at, _policy_list_cache
    auth.logout()
    _policies_cache.clear()
    _policy_list_cache = []
    _policy_cache_expires_at = 0.0
    _groups_cache.clear()
    clear_group_caches()
    return {"status": "logged_out"}


# ── Policy routes ────────────────────────────────────────────────────────────


@app.get("/api/policies", response_model=list[Policy], response_model_by_alias=True)
async def get_policies(refresh: bool = Query(False)) -> list[Policy]:
    """Fetch all policies from Graph API and cache them."""
    try:
        return await _load_policies(force_refresh=refresh)
    except RuntimeError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        logger.error("Failed to fetch policies: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to fetch policies: {e}")


@app.get("/api/policies/{policy_id}", response_model=Policy, response_model_by_alias=True)
async def get_policy(policy_id: str) -> Policy:
    """Get a single policy from cache."""
    await _ensure_policies_loaded()
    if policy_id in _policies_cache:
        return _policies_cache[policy_id]
    raise HTTPException(status_code=404, detail="Policy not found — fetch all policies first")


# ── Group routes ─────────────────────────────────────────────────────────────


@app.get("/api/groups")
async def list_all_groups() -> list[dict[str, Any]]:
    """Fetch all groups from the tenant."""
    cached = _groups_cache.get("all")
    if cached is not None:
        return cached

    client = _get_graph_client()
    try:
        from group_resolver import _build_group
        raw_groups = await client.get(
            "groups",
            params={"$select": "id,displayName,description,groupTypes,membershipRule", "$top": "999", "$orderby": "displayName", "$count": "true"},
        )
        groups = [_build_group(g).model_dump(by_alias=True) for g in raw_groups]
        _groups_cache.set("all", groups)
        return groups
    except RuntimeError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        logger.error("Failed to list groups: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to list groups: {e}")


@app.get("/api/groups/search")
async def search_groups_route(q: str = Query(..., min_length=1)) -> list[dict[str, Any]]:
    """Search groups by display name."""
    client = _get_graph_client()
    try:
        groups = await search_groups(client, q)
        return [g.model_dump(by_alias=True) for g in groups]
    except RuntimeError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        logger.error("Group search failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Group search failed: {e}")


@app.get("/api/groups/{group_id}")
async def get_group_route(group_id: str) -> dict[str, Any]:
    """Get a single group with transitive member count."""
    client = _get_graph_client()
    try:
        group = await get_group(client, group_id)
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")

        # Enrich with transitive member count
        members = await get_group_transitive_members(client, group_id)
        group.member_count = len(members)

        return group.model_dump(by_alias=True)
    except HTTPException:
        raise
    except RuntimeError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        logger.error("Failed to get group %s: %s", group_id, e)
        raise HTTPException(status_code=500, detail=f"Failed to get group: {e}")


@app.get("/api/groups/{group_id}/policies", response_model=list[GroupPolicyMapping], response_model_by_alias=True)
async def get_group_policies(
    group_id: str,
    include_all_users: bool = Query(True, alias="includeAllUsers"),
    include_all_devices: bool = Query(True, alias="includeAllDevices"),
) -> list[GroupPolicyMapping]:
    """Get all policies assigned to a group (direct, inherited, all users/devices)."""
    client = _get_graph_client()
    try:
        await _ensure_policies_loaded()
        all_policies = list(_policies_cache.values())
        mappings = await resolve_policies_for_group(client, group_id, all_policies)
        # Filter out All Users / All Devices mappings if requested
        if not include_all_users:
            mappings = [m for m in mappings if m.assignment_source != "all_users"]
        if not include_all_devices:
            mappings = [m for m in mappings if m.assignment_source != "all_devices"]
        return mappings
    except RuntimeError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        logger.error("Failed to resolve policies for group %s: %s", group_id, e)
        raise HTTPException(
            status_code=500, detail=f"Failed to resolve policies: {e}"
        )


@app.get("/api/policies/{policy_id}/groups")
async def get_policy_groups(policy_id: str) -> list[dict[str, Any]]:
    """Get all groups targeted by a policy."""
    try:
        await _ensure_policies_loaded()
        if policy_id not in _policies_cache:
            raise HTTPException(status_code=404, detail="Policy not found")
        policy = _policies_cache[policy_id]
        group_targets = resolve_groups_for_policy(policy)

        # Enrich with group details where possible
        client = _get_graph_client()
        enriched: list[dict[str, Any]] = []
        for target in group_targets:
            entry = dict(target)
            group_id = target.get("group_id")
            if group_id:
                try:
                    group = await get_group(client, group_id)
                    if group:
                        entry["group_name"] = group.display_name
                except Exception:
                    pass
            enriched.append(entry)

        return enriched
    except HTTPException:
        raise
    except RuntimeError as e:
        raise HTTPException(status_code=401, detail=str(e))


# ── Conflict analysis routes ─────────────────────────────────────────────────


@app.get("/api/analyze-conflicts", response_model_by_alias=True)
async def analyze_conflicts(
    platform: Optional[list[str]] = Query(None),
) -> dict[str, Any]:
    """Analyze all policies for overlapping settings tenant-wide."""
    try:
        await _ensure_policies_loaded()
        all_policies = list(_policies_cache.values())
        conflicts = analyze_all_conflicts(
            all_policies,
            selected_platforms=_normalize_platform_filters(platform),
        )
        stats = build_conflict_stats(conflicts)
        return {
            "conflicts": [c.model_dump(by_alias=True) for c in conflicts],
            "stats": stats,
        }
    except RuntimeError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        logger.error("Conflict analysis failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Conflict analysis failed: {e}")


@app.get("/api/analyze-conflicts/group/{group_id}", response_model_by_alias=True)
async def analyze_conflicts_for_group_route(
    group_id: str,
    include_all_users: bool = Query(True, alias="includeAllUsers"),
    include_all_devices: bool = Query(True, alias="includeAllDevices"),
    platform: Optional[list[str]] = Query(None),
) -> dict[str, Any]:
    """Analyze conflicts for policies targeting a specific group."""
    client = _get_graph_client()
    try:
        await _ensure_policies_loaded()
        all_policies = list(_policies_cache.values())
        mappings = await resolve_policies_for_group(client, group_id, all_policies)
        if not include_all_users:
            mappings = [m for m in mappings if m.assignment_source != "all_users"]
        if not include_all_devices:
            mappings = [m for m in mappings if m.assignment_source != "all_devices"]
        mappings_dicts = [m.model_dump(by_alias=True) for m in mappings]
        conflicts = analyze_conflicts_for_group(
            group_id,
            all_policies,
            mappings_dicts,
            selected_platforms=_normalize_platform_filters(platform),
        )
        stats = build_conflict_stats(conflicts)
        return {
            "conflicts": [c.model_dump(by_alias=True) for c in conflicts],
            "stats": stats,
        }
    except HTTPException:
        raise
    except RuntimeError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        logger.error("Conflict analysis for group %s failed: %s", group_id, e)
        raise HTTPException(
            status_code=500, detail=f"Conflict analysis failed: {e}"
        )


@app.get("/api/analyze-conflicts/target/{target}", response_model_by_alias=True)
async def analyze_conflicts_for_target_route(
    target: str,
    platform: Optional[list[str]] = Query(None),
) -> dict[str, Any]:
    """Analyze conflicts for All Users or All Devices."""
    if target not in ("all_users", "all_devices"):
        raise HTTPException(status_code=400, detail="target must be 'all_users' or 'all_devices'")
    try:
        await _ensure_policies_loaded()
        all_policies = list(_policies_cache.values())
        conflicts = analyze_conflicts_for_target(
            target,
            all_policies,
            selected_platforms=_normalize_platform_filters(platform),
        )
        stats = build_conflict_stats(conflicts)
        return {
            "conflicts": [c.model_dump(by_alias=True) for c in conflicts],
            "stats": stats,
        }
    except RuntimeError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        logger.error("Conflict analysis for target %s failed: %s", target, e)
        raise HTTPException(status_code=500, detail=f"Conflict analysis failed: {e}")


@app.get("/api/analyze-conflicts/policy/{policy_id}", response_model_by_alias=True)
async def analyze_conflicts_for_policy_route(
    policy_id: str,
    platform: Optional[list[str]] = Query(None),
) -> dict[str, Any]:
    """Analyze conflicts for a specific policy against all others with shared assignments."""
    try:
        await _ensure_policies_loaded()
        if policy_id not in _policies_cache:
            raise HTTPException(status_code=404, detail="Policy not found")
        all_policies = list(_policies_cache.values())
        conflicts = analyze_conflicts_for_policy(
            policy_id,
            all_policies,
            selected_platforms=_normalize_platform_filters(platform),
        )
        stats = build_conflict_stats(conflicts)
        return {
            "conflicts": [c.model_dump(by_alias=True) for c in conflicts],
            "stats": stats,
        }
    except RuntimeError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        logger.error("Conflict analysis for policy %s failed: %s", policy_id, e)
        raise HTTPException(
            status_code=500, detail=f"Conflict analysis failed: {e}"
        )


# ── App lifecycle ────────────────────────────────────────────────────────────


@app.on_event("shutdown")
async def shutdown() -> None:
    if _graph_client:
        await _graph_client.close()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=settings.backend_port)
