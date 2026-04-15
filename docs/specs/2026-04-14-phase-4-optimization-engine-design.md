# Phase 4 — Optimization Engine Design Spec

**Date:** 2026-04-14  
**Status:** Approved  
**Scope:** Read-only policy consolidation and fragmentation analysis

---

## Goal

Add a Phase 4 Optimization Engine that helps identify where a tenant's Intune policy estate can be streamlined without making any write-back changes.

The engine should answer questions like:

- Which policy domains are fragmented across too many profiles?
- Which groups or global targets receive multiple non-conflicting policies that could plausibly be consolidated?
- Which policy families look intentionally layered versus unnecessarily split?

This phase is strictly read-only. It must not generate policy changes, draft JSON, import packages, or write back to Microsoft Graph.

---

## Problem

The tenant has a large number of policies that are functionally adjacent:

- multiple Edge-related policies
- multiple Defender-related policies
- multiple Windows Update / Autopatch-related policies
- multiple baseline and restriction profiles that touch overlapping areas of the OS

The current app can show conflicts and overlaps, but it does not yet answer the operational question:

> "Where is my policy estate fragmented in a way that could be simplified?"

Simple name-based heuristics are not reliable enough for this tenant. Recommendations need to be grounded in:

- exact normalized settings
- actual assignment overlap
- actual platform overlap
- conflict status

---

## Non-Goals

Phase 4 will not:

- modify or create Intune policies
- generate migration packages or merge payloads
- produce automated remediation steps
- infer precedence or effective winner beyond current overlap/conflict analysis
- show every detected domain in the tenant if that produces low-signal noise

---

## Product Direction

Phase 4 should focus on high-signal recommendations only.

The first version should ship two recommendation classes:

1. `consolidation_candidates`
   Multiple policies in the same domain target the same audience on the same platform with low or no conflict pressure.

2. `fragmentation_hotspots`
   A policy area is spread across too many profiles for the same audience/platform, even when a clean merge recommendation is less certain.

`broad_assignment_candidates` is deferred unless it falls out naturally from the same data model.

---

## Core Approach

The engine should use a **setting-first clustering model** with assignment-aware scoring.

This is preferred over name-based clustering because:

- it is anchored in real configured settings
- it survives inconsistent naming
- it can detect adjacent policy families even when policy titles vary
- it is explainable in terms an admin can validate

The scoring model should combine:

- same effective audience
- same platform
- same functional domain
- number of involved policies
- amount of exact setting overlap
- amount of conflict pressure
- fragmentation level

---

## Data Sources

Phase 4 should reuse existing in-memory policy data and the exact-setting extraction already used by the conflict analyzer.

It should not trigger a second policy ingestion pipeline or fetch a different copy of the tenant state.

Primary reused inputs:

- normalized policy objects from `policy_fetcher.py`
- exact-setting extraction from `conflict_analyzer.py`
- assignment overlap logic and platform normalization from conflict analysis

---

## Domain Model

### 1. Exact Settings

All optimization analysis must start from exact normalized settings.

Important rule:

- policies may only be considered "the same setting" if they match the exact normalized setting key already used by the conflict analyzer

That preserves the stricter matching work already completed:

- no cross-platform matching
- no script metadata matching
- no Wi-Fi identity payload matching
- no OMA payload matching
- no certificate profile metadata matching
- no matching across unrelated raw device configuration schemas

### 2. Domains

Each exact setting should also be mapped into a broader functional domain for clustering and presentation.

Initial examples:

- `Edge`
- `Defender`
- `Firewall`
- `Windows Update`
- `BitLocker`
- `Identity`
- `Browser`
- `Device Restrictions`
- `Office Updates`
- `Credential Guard / Device Guard`
- `Start Menu / Shell`
- `Android Restrictions`

Domain mapping should be driven primarily by normalized setting paths and known path segments, not by policy names.

Settings that cannot be confidently classified should fall into:

- `Other`

Low-signal `Other` findings should be suppressed in v1 unless they still score highly on consolidation impact.

### 3. Audience Buckets

Optimization findings should be generated within audience buckets.

An audience bucket is defined by:

- effective assignment target
  - group
  - all users
  - all devices
- normalized platform
- domain

This prevents recommendations that mix:

- different platforms
- unrelated assignment scopes
- unrelated policy domains

---

## Analysis Pipeline

### Pass 1: Extract and Annotate Settings

For each policy:

- extract exact normalized settings
- annotate each setting with:
  - domain
  - platform
  - policy type
  - policy id
  - policy name
  - effective assignment targets

### Pass 2: Build Domain + Audience Clusters

Group settings into clusters keyed by:

- domain
- audience bucket
- platform

Within each cluster, calculate:

- number of policies
- number of unique exact settings
- number of shared exact settings
- number of settings unique to each policy
- conflict count
- matching overlap count

### Pass 3: Score Findings

Compute a confidence/impact score for each cluster.

Score should increase when:

- the same audience receives many policies in the same domain
- the same platform is targeted
- the policies share many exact settings
- conflict pressure is low
- the cluster spans multiple policies that look administratively fragmented

Score should decrease when:

- conflict count is high
- domain classification is weak
- policies share too few settings
- the cluster appears intentionally segmented

### Pass 4: Emit Recommendations

Only emit high-signal findings.

Each finding should include:

- recommendation type
- domain label
- platform label
- audience summary
- involved policy list
- shared setting count
- unique setting count
- conflict count
- confidence score
- impact score
- rationale text

---

## Recommendation Types

### Consolidation Candidate

Used when:

- 2+ policies share the same audience and platform
- they belong to the same domain
- they have no or very low conflict pressure
- they show enough exact-setting overlap or adjacency to suggest unnecessary fragmentation

Example rationale:

> "Five Windows Update policies target the same Windows audience with no conflicting settings and substantial overlap, suggesting they may be administratively fragmented."

### Fragmentation Hotspot

Used when:

- a domain/audience/platform area is spread across many policies
- overlap is meaningful enough to indicate sprawl
- merge confidence is lower than a consolidation candidate

Example rationale:

> "This Windows device restrictions area is distributed across seven policies for the same audience. Even without a direct merge recommendation, the estate appears fragmented."

---

## API Design

Add a new backend route for read-only optimization analysis.

Recommended route:

- `GET /api/optimize`

Supported query filters in v1:

- `platform=<value>` repeated
- optional domain filter if the frontend needs it immediately

Response shape should be purpose-built for the Optimization tab and not reuse the generic conflict response model.

Suggested payload shape:

```json
{
  "summary": {
    "totalFindings": 12,
    "consolidationCandidates": 7,
    "fragmentationHotspots": 5,
    "highConfidenceCount": 6
  },
  "findings": [
    {
      "findingType": "consolidation_candidate",
      "domain": "Edge",
      "platforms": ["windows"],
      "audience": {
        "type": "group",
        "label": "Corp Windows 11"
      },
      "confidenceScore": 87,
      "impactScore": 73,
      "policyCount": 4,
      "sharedSettingCount": 18,
      "uniqueSettingCount": 7,
      "conflictCount": 0,
      "rationale": "Four Edge policies target the same Windows audience with no conflicting settings and significant overlap.",
      "policies": [
        {
          "policyId": "123",
          "policyName": "Corp-Win11-Azure - Edge Browser Profile",
          "policyType": "deviceConfiguration"
        }
      ]
    }
  ]
}
```

---

## Frontend Design

Add or enable an `Optimization` tab focused on ranked recommendations.

The first version should optimize for scanning and actionability, not completeness.

### Layout

- summary cards at the top
- filter controls for:
  - platform
  - domain
  - recommendation type
- ranked finding cards below

### Finding Card

Each card should show:

- domain
- recommendation type
- confidence score
- impact score
- audience summary
- number of involved policies
- short rationale

Expanded state should show:

- involved policies
- policy types
- overlap summary
- conflict summary
- platform(s)

### Sorting

Default sort:

1. confidence score descending
2. impact score descending
3. policy count descending

### Presentation Principle

Do not show low-confidence findings in v1.

The user should see a short, opinionated list of likely consolidation opportunities, not a dump of every domain detected in the tenant.

---

## Scoring Heuristics

The exact formula can evolve, but the first implementation should roughly follow:

### Confidence Inputs

- same audience
- same platform
- same domain
- exact-setting overlap ratio
- conflict penalty
- policy-count bonus

### Impact Inputs

- number of policies involved
- number of repeated/shared settings
- fragmentation ratio
- audience breadth

### Suppression Rules

Suppress findings when:

- confidence is below threshold
- domain is `Other` and weakly supported
- only one policy is involved
- the cluster has too little overlap to be actionable

---

## Backend File Plan

- `backend/optimization_engine.py`
  - implement clustering, scoring, and recommendation generation
- `backend/main.py`
  - expose optimization route
- `backend/models.py`
  - add response models for optimization findings
- `backend/conflict_analyzer.py`
  - reuse exact-setting extraction helpers where needed rather than duplicating logic

---

## Frontend File Plan

- `frontend/src/components/Optimization.tsx`
  - render summary, filters, and ranked findings
- `frontend/src/services/api.ts`
  - add optimization API client
- `frontend/src/types/index.ts`
  - add types if shared types are needed client-side
- `frontend/src/App.tsx`
  - enable Optimization tab and state wiring

---

## Testing Strategy

### Backend

Add unit tests that prove:

- findings only use exact normalized setting matches
- different raw schemas do not merge into one recommendation
- different platforms do not merge into one recommendation
- conflict-heavy clusters are penalized or suppressed
- high-overlap same-audience clusters produce consolidation findings
- fragmented same-domain clusters produce hotspot findings

### Frontend

Add tests that prove:

- findings render in ranked order
- filters work
- hidden low-confidence findings do not appear
- expanded cards show the intended policy details

---

## Success Criteria

Phase 4 is successful when:

- the engine returns a small, high-signal list of consolidation opportunities
- findings are explainable in terms of exact settings, domains, and shared audience
- the UI helps an admin quickly spot where policy sprawl is likely unnecessary
- nothing in the workflow attempts to create or modify Intune policies

---

## Out of Scope for Phase 4

- automated merge plans
- export format customization for optimization findings
- recommendation history over time
- tenant benchmarking
- write-back actions

