from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable, Optional

from conflict_analyzer import (
    _extract_settings,
    _filter_policies_by_platforms,
    _get_assigned_group_ids,
    _platform_bucket_key,
    _platform_tokens,
)
from models import (
    OptimizationAnalysisResult,
    OptimizationFindingV1,
    OptimizationPolicyPreview,
    OptimizationRecommendationType,
    OptimizationSummary,
    Policy,
)


_DOMAIN_RULES: tuple[tuple[str, str], ...] = (
    ("edge", "Edge"),
    ("defender", "Defender"),
    ("firewall", "Firewall"),
    ("bitlocker", "BitLocker"),
    ("update", "Windows Update"),
    ("autopatch", "Windows Update"),
    ("windowsupdate", "Windows Update"),
    ("credentialguard", "Credential Guard / Device Guard"),
    ("deviceguard", "Credential Guard / Device Guard"),
    ("browser", "Browser"),
    ("office", "Office"),
    ("start", "Start Menu / Shell"),
    ("shell", "Start Menu / Shell"),
    ("android", "Android Restrictions"),
    ("password", "Identity"),
)

_PLATFORM_LABELS = {
    "windows": "Windows",
    "macos": "macOS",
    "ios": "iOS/iPadOS",
    "android": "Android",
    "linux": "Linux",
    "unknown": "Unknown",
    "all": "All Platforms",
}


def _classify_domain(setting_key: str, display_name: str) -> str:
    haystack = f"{setting_key} {display_name}".lower()
    for marker, domain in _DOMAIN_RULES:
        if marker in haystack:
            return domain
    return "Other"


def _platform_labels(platform_key: str) -> list[str]:
    labels = [_PLATFORM_LABELS.get(token, token.title()) for token in platform_key.split("|") if token]
    return labels or ["Unknown"]


def _audience_targets(
    policy: Policy,
    group_name_by_id: Optional[dict[str, str]] = None,
) -> list[tuple[str, str]]:
    targets: list[tuple[str, str]] = []
    for assignment in policy.assignments:
        target = assignment.get("target", {})
        odata_type = str(target.get("@odata.type", ""))
        group_id = str(target.get("groupId", "")).strip()
        if group_id and "exclusion" not in odata_type.lower():
            targets.append((f"group:{group_id}", group_name_by_id.get(group_id, group_id) if group_name_by_id else group_id))
        elif "allLicensedUsers" in odata_type:
            targets.append(("all_users", "All Users"))
        elif "allDevices" in odata_type:
            targets.append(("all_devices", "All Devices"))

    if not targets:
        for synthetic in _get_assigned_group_ids(policy):
            if synthetic == "__ALL__":
                targets.append(("all_assigned", "All Assigned"))
            else:
                targets.append((
                    f"group:{synthetic}",
                    group_name_by_id.get(synthetic, synthetic) if group_name_by_id else synthetic,
                ))
    return targets


def _score_cluster(
    *,
    policy_count: int,
    shared_setting_count: int,
    unique_setting_count: int,
    conflict_count: int,
) -> tuple[int, int]:
    impact = min(100, policy_count * 18 + unique_setting_count * 8 + shared_setting_count * 10)
    confidence = 40 + policy_count * 10 + shared_setting_count * 12 - conflict_count * 15
    if unique_setting_count >= 3:
        confidence += 5
    return max(0, min(100, confidence)), max(0, impact)


def _make_policy_preview(policy: Policy, settings: list[dict[str, Any]]) -> OptimizationPolicyPreview:
    return OptimizationPolicyPreview(
        policy_id=policy.id,
        policy_name=policy.display_name,
        policy_type=policy.policy_type.value,
        platform=next(iter(_platform_labels(_platform_bucket_key(policy))), policy.platform),
        setting_count=len(settings),
    )


def _make_finding(
    *,
    recommendation_type: OptimizationRecommendationType,
    domain: str,
    audience: str,
    platform_key: str,
    policies: list[Policy],
    policy_settings: dict[str, list[dict[str, Any]]],
    shared_setting_count: int,
    matching_setting_count: int,
    conflict_count: int,
) -> OptimizationFindingV1:
    unique_setting_keys = {
        entry["setting_key"]
        for policy in policies
        for entry in policy_settings[policy.id]
    }
    unique_setting_count = len(unique_setting_keys)
    confidence_score, impact_score = _score_cluster(
        policy_count=len(policies),
        shared_setting_count=shared_setting_count,
        unique_setting_count=unique_setting_count,
        conflict_count=conflict_count,
    )

    top_settings = sorted(
        {
            entry.get("display_name") or entry["setting_key"]
            for policy in policies
            for entry in policy_settings[policy.id]
        }
    )[:5]
    policy_previews = [_make_policy_preview(policy, policy_settings[policy.id]) for policy in policies]
    title = (
        f"Consolidate {domain} policies for {audience}"
        if recommendation_type == OptimizationRecommendationType.CONSOLIDATION_CANDIDATE
        else f"Reduce {domain} policy fragmentation for {audience}"
    )
    summary = (
        f"{len(policies)} policies target the same audience on {', '.join(_platform_labels(platform_key))}."
    )
    rationale = (
        f"{shared_setting_count} shared exact settings, {conflict_count} conflicts, "
        f"{unique_setting_count} total exact settings in this domain cluster."
    )

    return OptimizationFindingV1(
        recommendation_type=recommendation_type,
        title=title,
        summary=summary,
        rationale=rationale,
        domain=domain,
        audience=audience,
        platforms=_platform_labels(platform_key),
        confidence_score=confidence_score,
        impact_score=impact_score,
        policy_count=len(policies),
        shared_setting_count=shared_setting_count,
        unique_setting_count=unique_setting_count,
        matching_setting_count=matching_setting_count,
        conflict_count=conflict_count,
        example_settings=top_settings,
        policies=policy_previews,
    )


def _iter_domain_clusters(
    policies: Iterable[Policy],
    group_name_by_id: Optional[dict[str, str]] = None,
) -> dict[tuple[str, str, str, str], dict[str, Any]]:
    clusters: dict[tuple[str, str, str, str], dict[str, Any]] = {}

    for policy in policies:
        policy_entries = _extract_settings(policy)
        if not policy_entries:
            continue

        by_domain: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for entry in policy_entries:
            domain = _classify_domain(entry["setting_key"], entry.get("display_name", ""))
            by_domain[domain].append(entry)

        for audience_key, audience_label in _audience_targets(policy, group_name_by_id):
            for domain, entries in by_domain.items():
                cluster_key = (
                    domain,
                    audience_key,
                    _platform_bucket_key(policy),
                    policy.policy_type.value,
                )
                cluster = clusters.setdefault(
                    cluster_key,
                    {
                        "domain": domain,
                        "audience": audience_label,
                        "platform_key": _platform_bucket_key(policy),
                        "policy_type": policy.policy_type.value,
                        "policies": {},
                    },
                )
                cluster["policies"][policy.id] = {
                    "policy": policy,
                    "settings": entries,
                }

    return clusters


def analyze_optimization_opportunities(
    policies: list[Policy],
    selected_platforms: Optional[set[str]] = None,
    group_name_by_id: Optional[dict[str, str]] = None,
) -> OptimizationAnalysisResult:
    filtered_policies = _filter_policies_by_platforms(policies, selected_platforms)
    clusters = _iter_domain_clusters(filtered_policies, group_name_by_id)
    findings: list[OptimizationFindingV1] = []

    for (domain, _audience_key, platform_key, _policy_type), cluster in clusters.items():
        if domain == "Other":
            continue

        policy_map = cluster["policies"]
        if len(policy_map) < 2:
            continue

        policies_in_cluster = [entry["policy"] for entry in policy_map.values()]
        policy_settings = {
            policy_id: entry["settings"]
            for policy_id, entry in policy_map.items()
        }

        settings_map: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for entries in policy_settings.values():
            for setting in entries:
                settings_map[setting["setting_key"]].append(setting)

        shared_setting_count = 0
        matching_setting_count = 0
        conflict_count = 0
        for entries in settings_map.values():
            if len(entries) < 2:
                continue
            shared_setting_count += 1
            distinct_values = {repr(entry["value"]) for entry in entries}
            if len(distinct_values) > 1:
                conflict_count += 1
            else:
                matching_setting_count += 1

        unique_setting_count = len(settings_map)
        recommendation_type: OptimizationRecommendationType | None = None
        if conflict_count == 0 and shared_setting_count >= 1:
            recommendation_type = OptimizationRecommendationType.CONSOLIDATION_CANDIDATE
        elif len(policies_in_cluster) >= 3 and unique_setting_count >= 3:
            recommendation_type = OptimizationRecommendationType.FRAGMENTATION_HOTSPOT

        if recommendation_type is None:
            continue

        findings.append(
            _make_finding(
                recommendation_type=recommendation_type,
                domain=domain,
                audience=cluster["audience"],
                platform_key=platform_key,
                policies=sorted(policies_in_cluster, key=lambda policy: policy.display_name.lower()),
                policy_settings=policy_settings,
                shared_setting_count=shared_setting_count,
                matching_setting_count=matching_setting_count,
                conflict_count=conflict_count,
            )
        )

    findings.sort(
        key=lambda finding: (
            -finding.confidence_score,
            -finding.impact_score,
            finding.domain,
            finding.audience,
        )
    )

    summary = OptimizationSummary(
        total_findings=len(findings),
        consolidation_candidates=sum(
            1
            for finding in findings
            if finding.recommendation_type == OptimizationRecommendationType.CONSOLIDATION_CANDIDATE
        ),
        fragmentation_hotspots=sum(
            1
            for finding in findings
            if finding.recommendation_type == OptimizationRecommendationType.FRAGMENTATION_HOTSPOT
        ),
        domains=sorted({finding.domain for finding in findings}),
        platforms=sorted({platform for finding in findings for platform in finding.platforms}),
    )
    return OptimizationAnalysisResult(summary=summary, findings=findings)
