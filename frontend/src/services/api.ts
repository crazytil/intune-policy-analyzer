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

export async function getGroupPolicies(groupId: string): Promise<GroupPolicyMapping> {
  return request<GroupPolicyMapping>(`${BASE}/groups/${encodeURIComponent(groupId)}/policies`)
}

export async function getPolicyGroups(policyId: string): Promise<{ groups: Array<Group & { assignmentType: string; filter?: string }> }> {
  return request<{ groups: Array<Group & { assignmentType: string; filter?: string }> }>(`${BASE}/policies/${encodeURIComponent(policyId)}/groups`)
}
