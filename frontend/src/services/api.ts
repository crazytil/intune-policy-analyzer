import type { AuthStatus, Policy, Group, GroupPolicyMapping } from '../types'

const BASE = '/api'

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(url, options)
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText)
    throw new Error(`API error ${res.status}: ${text}`)
  }
  return res.json() as Promise<T>
}

export async function getAuthStatus(): Promise<AuthStatus> {
  return request<AuthStatus>(`${BASE}/auth/status`)
}

export async function login(): Promise<AuthStatus> {
  return request<AuthStatus>(`${BASE}/auth/login`, { method: 'POST' })
}

export async function logout(): Promise<void> {
  await request<unknown>(`${BASE}/auth/logout`, { method: 'POST' })
}

export async function fetchPolicies(): Promise<Policy[]> {
  return request<Policy[]>(`${BASE}/policies`)
}

export async function searchGroups(query: string): Promise<Group[]> {
  return request<Group[]>(`${BASE}/groups/search?q=${encodeURIComponent(query)}`)
}

export async function getGroupPolicies(groupId: string): Promise<GroupPolicyMapping[]> {
  return request<GroupPolicyMapping[]>(`${BASE}/groups/${encodeURIComponent(groupId)}/policies`)
}

export interface PolicyGroupTarget {
  group_id: string | null
  group_name?: string
  assignment_type: string
  filter_id?: string | null
  filter_type?: string | null
}

export async function getPolicyGroups(policyId: string): Promise<PolicyGroupTarget[]> {
  return request<PolicyGroupTarget[]>(`${BASE}/policies/${encodeURIComponent(policyId)}/groups`)
}

export interface ConflictPolicy {
  policyId: string
  policyName: string
  policyType: string
  value: unknown
}

export interface ConflictItem {
  settingKey: string
  settingLabel: string
  hasDifferentValues: boolean
  policies: ConflictPolicy[]
}

export interface ConflictStats {
  totalSharedSettings: number
  conflictCount: number
  duplicateCount: number
  affectedPolicies: number
}

export interface ConflictAnalysisResult {
  conflicts: ConflictItem[]
  stats: ConflictStats
}

export async function analyzeConflicts(): Promise<ConflictAnalysisResult> {
  return request<ConflictAnalysisResult>(`${BASE}/analyze-conflicts`)
}

export async function analyzeConflictsForGroup(groupId: string): Promise<ConflictAnalysisResult> {
  return request<ConflictAnalysisResult>(`${BASE}/analyze-conflicts/group/${encodeURIComponent(groupId)}`)
}
