# Phase 4 Optimization Engine V1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a read-only optimization engine that surfaces high-signal consolidation and fragmentation recommendations from the existing Intune policy data.

**Architecture:** Reuse the conflict analyzer's exact-setting extraction and assignment/platform normalization to build domain-and-audience clusters server-side. Expose a single optimization API and render ranked recommendation cards in a new frontend tab.

**Tech Stack:** FastAPI, Pydantic, Python unittest, React, TypeScript, Vite

---

### Task 1: Backend Models And Engine Contract

**Files:**
- Create: `backend/optimization_engine.py`
- Modify: `backend/models.py`
- Test: `tests/test_optimization_engine.py`

- [ ] Add failing tests for domain classification, audience clustering, and recommendation scoring.
- [ ] Add Pydantic response models for optimization summary, findings, and related policy previews.
- [ ] Implement the optimization engine with two finding types only: `consolidationCandidate` and `fragmentationHotspot`.
- [ ] Re-run `backend/venv/bin/python -m unittest tests.test_optimization_engine -v`.

### Task 2: Backend Route Integration

**Files:**
- Modify: `backend/main.py`
- Test: `tests/test_optimization_engine.py`

- [ ] Add an optimization API route that reuses the cached policy set and supports optional platform filtering.
- [ ] Return camelCase API payloads that match the frontend contract.
- [ ] Re-run `backend/venv/bin/python -m unittest tests.test_optimization_engine tests.test_conflict_analyzer tests.test_cache_utils tests.test_policy_fetcher -v`.

### Task 3: Frontend Optimization Tab

**Files:**
- Create: `frontend/src/components/Optimization.tsx`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/services/api.ts`
- Modify: `frontend/src/types/index.ts`

- [ ] Add API types and fetch helpers for optimization findings.
- [ ] Replace the disabled Optimization tab with a read-only recommendations view.
- [ ] Support platform and domain filtering, plus expanded finding details.
- [ ] Re-run `npm run build`.

### Task 4: Final Verification

**Files:**
- Modify as needed from prior tasks

- [ ] Run backend unit tests for optimization plus existing regression coverage.
- [ ] Run frontend production build.
- [ ] Summarize what shipped as V1 and what remains intentionally deferred.
