from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

import auth
from config import settings
from graph_client import GraphClient
from group_resolver import (
    get_group,
    get_group_transitive_members,
    resolve_groups_for_policy,
    resolve_policies_for_group,
    search_groups,
)
from conflict_analyzer import analyze_all_conflicts, analyze_conflicts_for_group, analyze_conflicts_for_policy, build_conflict_stats
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
_graph_client: Optional[GraphClient] = None


def _get_graph_client() -> GraphClient:
    global _graph_client
    if _graph_client is None:
        _graph_client = GraphClient()
    return _graph_client


# ── Auth routes ──────────────────────────────────────────────────────────────


@app.get("/api/auth/status", response_model=AuthStatus, response_model_by_alias=True)
async def auth_status() -> AuthStatus:
    return auth.get_auth_status()


@app.post("/api/auth/login", response_model=AuthStatus, response_model_by_alias=True)
async def auth_login() -> AuthStatus:
    try:
        return auth.initiate_auth()
    except Exception as e:
        logger.error("Login failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Login failed: {e}")


@app.post("/api/auth/logout")
async def auth_logout() -> dict[str, str]:
    auth.logout()
    _policies_cache.clear()
    return {"status": "logged_out"}


# ── Policy routes ────────────────────────────────────────────────────────────


@app.get("/api/policies", response_model=list[Policy], response_model_by_alias=True)
async def get_policies() -> list[Policy]:
    """Fetch all policies from Graph API and cache them."""
    client = _get_graph_client()
    try:
        policies = await fetch_all_policies(client)
        _policies_cache.clear()
        for p in policies:
            _policies_cache[p.id] = p
        return policies
    except RuntimeError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        logger.error("Failed to fetch policies: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to fetch policies: {e}")


@app.get("/api/policies/{policy_id}", response_model=Policy, response_model_by_alias=True)
async def get_policy(policy_id: str) -> Policy:
    """Get a single policy from cache."""
    if policy_id in _policies_cache:
        return _policies_cache[policy_id]
    raise HTTPException(status_code=404, detail="Policy not found — fetch all policies first")


# ── Group routes ─────────────────────────────────────────────────────────────


@app.get("/api/groups")
async def list_all_groups() -> list[dict[str, Any]]:
    """Fetch all groups from the tenant."""
    client = _get_graph_client()
    try:
        from group_resolver import _build_group
        raw_groups = await client.get(
            "groups",
            params={"$select": "id,displayName,description,groupTypes,membershipRule", "$top": "999", "$orderby": "displayName"},
        )
        return [_build_group(g).model_dump(by_alias=True) for g in raw_groups]
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
async def get_group_policies(group_id: str) -> list[GroupPolicyMapping]:
    """Get all policies assigned to a group (direct, inherited, all users/devices)."""
    if not _policies_cache:
        raise HTTPException(
            status_code=400,
            detail="No policies cached — call GET /api/policies first",
        )
    client = _get_graph_client()
    try:
        all_policies = list(_policies_cache.values())
        return await resolve_policies_for_group(client, group_id, all_policies)
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
    if policy_id not in _policies_cache:
        raise HTTPException(
            status_code=404,
            detail="Policy not found — call GET /api/policies first",
        )
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


# ── Conflict analysis routes ─────────────────────────────────────────────────


@app.get("/api/analyze-conflicts", response_model_by_alias=True)
async def analyze_conflicts() -> dict[str, Any]:
    """Analyze all policies for overlapping settings tenant-wide."""
    if not _policies_cache:
        raise HTTPException(
            status_code=400,
            detail="No policies cached — call GET /api/policies first",
        )
    all_policies = list(_policies_cache.values())
    try:
        conflicts = analyze_all_conflicts(all_policies)
        stats = build_conflict_stats(conflicts)
        return {
            "conflicts": [c.model_dump(by_alias=True) for c in conflicts],
            "stats": stats,
        }
    except Exception as e:
        logger.error("Conflict analysis failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Conflict analysis failed: {e}")


@app.get("/api/analyze-conflicts/group/{group_id}", response_model_by_alias=True)
async def analyze_conflicts_for_group_route(group_id: str) -> dict[str, Any]:
    """Analyze conflicts for policies targeting a specific group."""
    if not _policies_cache:
        raise HTTPException(
            status_code=400,
            detail="No policies cached — call GET /api/policies first",
        )
    client = _get_graph_client()
    all_policies = list(_policies_cache.values())
    try:
        mappings = await resolve_policies_for_group(client, group_id, all_policies)
        mappings_dicts = [m.model_dump(by_alias=True) for m in mappings]
        conflicts = analyze_conflicts_for_group(group_id, all_policies, mappings_dicts)
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


@app.get("/api/analyze-conflicts/policy/{policy_id}", response_model_by_alias=True)
async def analyze_conflicts_for_policy_route(policy_id: str) -> dict[str, Any]:
    """Analyze conflicts for a specific policy against all others with shared assignments."""
    if not _policies_cache:
        raise HTTPException(
            status_code=400,
            detail="No policies cached — call GET /api/policies first",
        )
    if policy_id not in _policies_cache:
        raise HTTPException(status_code=404, detail="Policy not found")
    all_policies = list(_policies_cache.values())
    try:
        conflicts = analyze_conflicts_for_policy(policy_id, all_policies)
        stats = build_conflict_stats(conflicts)
        return {
            "conflicts": [c.model_dump(by_alias=True) for c in conflicts],
            "stats": stats,
        }
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
