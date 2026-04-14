import type {
  AuthStatus,
  Group,
  GroupPolicyMapping,
  OptimizationAnalysisResult,
  Policy,
} from '../types'

const BASE = '/api'
const inflightRequests = new Map<string, Promise<unknown>>()

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const method = options?.method ?? 'GET'
  const dedupeKey = method === 'GET' ? `${method}:${url}` : null

  if (dedupeKey) {
    const existing = inflightRequests.get(dedupeKey)
    if (existing) {
      return existing as Promise<T>
    }
  }

  const execute = async () => {
    const res = await fetch(url, options)
    if (!res.ok) {
      const text = await res.text().catch(() => res.statusText)
      throw new Error(`API error ${res.status}: ${text}`)
    }
    return res.json() as Promise<T>
  }

  const promise = execute()
  if (dedupeKey) {
    inflightRequests.set(dedupeKey, promise)
  }

  try {
    return await promise
  } finally {
    if (dedupeKey) {
      inflightRequests.delete(dedupeKey)
    }
  }
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

export async function fetchPolicies(options?: { refresh?: boolean }): Promise<Policy[]> {
  const qs = options?.refresh ? '?refresh=true' : ''
  return request<Policy[]>(`${BASE}/policies${qs}`)
}

export async function fetchAllGroups(): Promise<Group[]> {
  return request<Group[]>(`${BASE}/groups`)
}

export async function searchGroups(query: string): Promise<Group[]> {
  return request<Group[]>(`${BASE}/groups/search?q=${encodeURIComponent(query)}`)
}

export async function getGroupPolicies(
  groupId: string,
  options?: { includeAllUsers?: boolean; includeAllDevices?: boolean },
): Promise<GroupPolicyMapping[]> {
  const params = new URLSearchParams()
  if (options?.includeAllUsers === false) params.set('includeAllUsers', 'false')
  if (options?.includeAllDevices === false) params.set('includeAllDevices', 'false')
  const qs = params.toString()
  return request<GroupPolicyMapping[]>(
    `${BASE}/groups/${encodeURIComponent(groupId)}/policies${qs ? `?${qs}` : ''}`,
  )
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
  valueDisplay: string
}

export interface ConflictItem {
  settingKey: string
  settingLabel: string
  hasDifferentValues: boolean
  policies: ConflictPolicy[]
}

export interface ConflictStats {
  totalOverlapping: number
  conflictCount: number
  matchingCount: number
  affectedPolicies: number
}

export interface ConflictAnalysisResult {
  conflicts: ConflictItem[]
  stats: ConflictStats
}

function appendPlatformFilters(params: URLSearchParams, platforms?: string[]): void {
  for (const platform of platforms ?? []) {
    if (platform.trim()) params.append('platform', platform)
  }
}

export async function analyzeConflictsForGroup(
  groupId: string,
  options?: { includeAllUsers?: boolean; includeAllDevices?: boolean; platforms?: string[] },
): Promise<ConflictAnalysisResult> {
  const params = new URLSearchParams()
  if (options?.includeAllUsers === false) params.set('includeAllUsers', 'false')
  if (options?.includeAllDevices === false) params.set('includeAllDevices', 'false')
  appendPlatformFilters(params, options?.platforms)
  const qs = params.toString()
  return request<ConflictAnalysisResult>(
    `${BASE}/analyze-conflicts/group/${encodeURIComponent(groupId)}${qs ? `?${qs}` : ''}`,
  )
}

export async function analyzeConflicts(options?: { platforms?: string[] }): Promise<ConflictAnalysisResult> {
  const params = new URLSearchParams()
  appendPlatformFilters(params, options?.platforms)
  const qs = params.toString()
  return request<ConflictAnalysisResult>(`${BASE}/analyze-conflicts${qs ? `?${qs}` : ''}`)
}

export async function analyzeConflictsForPolicy(
  policyId: string,
  options?: { platforms?: string[] },
): Promise<ConflictAnalysisResult> {
  const params = new URLSearchParams()
  appendPlatformFilters(params, options?.platforms)
  const qs = params.toString()
  return request<ConflictAnalysisResult>(
    `${BASE}/analyze-conflicts/policy/${encodeURIComponent(policyId)}${qs ? `?${qs}` : ''}`,
  )
}

export async function analyzeConflictsForTarget(
  target: 'all_users' | 'all_devices',
  options?: { platforms?: string[] },
): Promise<ConflictAnalysisResult> {
  const params = new URLSearchParams()
  appendPlatformFilters(params, options?.platforms)
  const qs = params.toString()
  return request<ConflictAnalysisResult>(`${BASE}/analyze-conflicts/target/${target}${qs ? `?${qs}` : ''}`)
}

export async function analyzeOptimization(
  options?: { platforms?: string[] },
): Promise<OptimizationAnalysisResult> {
  const params = new URLSearchParams()
  appendPlatformFilters(params, options?.platforms)
  const qs = params.toString()
  return request<OptimizationAnalysisResult>(`${BASE}/optimize${qs ? `?${qs}` : ''}`)
}
