import { useState, useEffect, useMemo, useCallback } from 'react'
import type { Policy, Group } from '../types'
import { POLICY_TYPES } from '../types'
import { analyzeConflicts, analyzeConflictsForGroup, analyzeConflictsForPolicy, analyzeConflictsForTarget } from '../services/api'
import type { ConflictItem, ConflictStats } from '../services/api'

interface ConflictAnalyzerProps {
  policies: Policy[]
  groups: Group[]
}

type FilterMode = 'all' | 'conflicts' | 'matching'
type ScopeMode = 'all' | 'group' | 'policy'
type PlatformFilter = 'windows' | 'macos' | 'ios' | 'android' | 'linux' | 'unknown'

const FRIENDLY_SETTING_SEGMENTS: Record<string, string> = {
  allowarchivescanning: 'Allow Archive Scanning',
  allowfullscanremovabledrivescanning: 'Allow Full Scan Removable Drives Scanning',
  submitsamplesconsent: 'Submit Samples Consent',
}

const PLATFORM_FILTER_OPTIONS: Array<{ key: PlatformFilter; label: string }> = [
  { key: 'windows', label: 'Windows' },
  { key: 'macos', label: 'macOS' },
  { key: 'ios', label: 'iOS/iPadOS' },
  { key: 'android', label: 'Android' },
  { key: 'linux', label: 'Linux' },
  { key: 'unknown', label: 'Unknown' },
]

function Spinner({ className = 'h-5 w-5' }: { className?: string }) {
  return (
    <svg className={`animate-spin ${className}`} viewBox="0 0 24 24" fill="none">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
    </svg>
  )
}

function StatCard({ label, value, index, accent }: { label: string; value: number | string; index: string; accent?: string }) {
  const accentClass = accent === 'red'
    ? 'text-red-600 dark:text-red-400'
    : accent === 'green'
      ? 'text-green-600 dark:text-green-400'
      : accent === 'amber'
        ? 'text-amber-600 dark:text-amber-400'
        : ''
  return (
    <div className="border-t-2 border-slate-300 bg-white p-5 dark:border-slate-700 dark:bg-[#121b19] sm:p-6">
      <div className="flex items-center justify-between"><p className="text-xs font-semibold uppercase tracking-[0.13em] text-slate-600 dark:text-slate-300">{label}</p><span aria-hidden="true" className="font-mono text-[10px] text-slate-500 dark:text-slate-400">{index}</span></div>
      <p className={`mt-5 text-4xl font-semibold tracking-[-0.04em] tabular-nums ${accentClass}`}>{value}</p>
    </div>
  )
}

export default function ConflictAnalyzer({ policies, groups }: ConflictAnalyzerProps) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [conflicts, setConflicts] = useState<ConflictItem[] | null>(null)
  const [stats, setStats] = useState<ConflictStats | null>(null)
  const [filterMode, setFilterMode] = useState<FilterMode>('conflicts')
  const [search, setSearch] = useState('')
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set())

  // Scope selection
  const [scopeMode, setScopeMode] = useState<ScopeMode>('all')
  const [selectedGroupId, setSelectedGroupId] = useState<string>('')
  const [selectedPolicyId, setSelectedPolicyId] = useState<string>('')
  const [groupFilter, setGroupFilter] = useState('')
  const [policyFilter, setPolicyFilter] = useState('')
  const [includeAllUsers, setIncludeAllUsers] = useState(true)
  const [includeAllDevices, setIncludeAllDevices] = useState(true)
  const [selectedPlatforms, setSelectedPlatforms] = useState<PlatformFilter[]>([])

  const filteredGroups = groupFilter.trim()
    ? groups.filter((g) => g.displayName.toLowerCase().includes(groupFilter.toLowerCase()))
    : groups

  const filteredPolicies = policyFilter.trim()
    ? policies.filter((p) => p.displayName.toLowerCase().includes(policyFilter.toLowerCase()))
    : policies

  const isSpecialTarget = selectedGroupId === 'all_users' || selectedGroupId === 'all_devices'

  const availablePlatforms = useMemo(() => {
    const keys = new Set<PlatformFilter>()
    for (const policy of policies) {
      for (const key of normalizePlatformKeys(policy.platform)) {
        keys.add(key)
      }
    }
    return PLATFORM_FILTER_OPTIONS.filter((option) => keys.has(option.key))
  }, [policies])

  const scopeLabel = scopeMode === 'group'
    ? (selectedGroupId === 'all_users' ? 'All Users'
      : selectedGroupId === 'all_devices' ? 'All Devices'
      : groups.find((g) => g.id === selectedGroupId)?.displayName)
    : scopeMode === 'policy'
      ? policies.find((p) => p.id === selectedPolicyId)?.displayName
      : null

  const handleAnalyze = useCallback(async () => {
    setLoading(true)
    setError(null)
    setExpandedRows(new Set())
    try {
      let result
      if (scopeMode === 'group' && isSpecialTarget) {
        result = await analyzeConflictsForTarget(selectedGroupId as 'all_users' | 'all_devices', {
          platforms: selectedPlatforms,
        })
      } else if (scopeMode === 'group' && selectedGroupId) {
        result = await analyzeConflictsForGroup(selectedGroupId, {
          includeAllUsers,
          includeAllDevices,
          platforms: selectedPlatforms,
        })
      } else if (scopeMode === 'policy' && selectedPolicyId) {
        result = await analyzeConflictsForPolicy(selectedPolicyId, { platforms: selectedPlatforms })
      } else {
        result = await analyzeConflicts({ platforms: selectedPlatforms })
      }
      setConflicts(result.conflicts)
      setStats(result.stats)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Analysis failed')
    } finally {
      setLoading(false)
    }
  }, [scopeMode, selectedGroupId, selectedPolicyId, isSpecialTarget, includeAllUsers, includeAllDevices, selectedPlatforms])

  // Auto-analyze when scope changes
  useEffect(() => {
    if (scopeMode === 'all') {
      handleAnalyze()
    }
  }, [scopeMode]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (scopeMode === 'group' && selectedGroupId) {
      handleAnalyze()
    }
  }, [selectedGroupId]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (scopeMode === 'policy' && selectedPolicyId) {
      handleAnalyze()
    }
  }, [selectedPolicyId]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (scopeMode === 'group' && selectedGroupId && !isSpecialTarget) {
      handleAnalyze()
    }
  }, [includeAllUsers, includeAllDevices]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (scopeMode === 'all') {
      handleAnalyze()
      return
    }
    if (scopeMode === 'group' && selectedGroupId) {
      handleAnalyze()
      return
    }
    if (scopeMode === 'policy' && selectedPolicyId) {
      handleAnalyze()
    }
  }, [selectedPlatforms]) // eslint-disable-line react-hooks/exhaustive-deps

  const toggleRow = (key: string) => {
    setExpandedRows((prev) => {
      const next = new Set(prev)
      next.has(key) ? next.delete(key) : next.add(key)
      return next
    })
  }

  const policyTypeLabel = (key: string) => {
    const info = POLICY_TYPES.find((t) => t.key === key)
    return info ? `${info.icon} ${info.label}` : key
  }

  const filtered = useMemo(() => {
    if (!conflicts) return []
    let items = conflicts
    if (filterMode === 'conflicts') items = items.filter((c) => c.hasDifferentValues)
    if (filterMode === 'matching') items = items.filter((c) => !c.hasDifferentValues)
    if (search.trim()) {
      const q = search.toLowerCase()
      items = items.filter(
        (c) =>
          c.settingKey.toLowerCase().includes(q) ||
          c.settingLabel.toLowerCase().includes(q) ||
          c.policies.some((p) => p.policyName.toLowerCase().includes(q)),
      )
    }
    return [...items].sort((a, b) => {
      if (a.hasDifferentValues === b.hasDifferentValues) return 0
      return a.hasDifferentValues ? -1 : 1
    })
  }, [conflicts, filterMode, search])

  const hasAnalyzed = conflicts !== null

  return (
    <div className="space-y-8">
      <header>
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[#147d72] dark:text-[#6ee7d8]">Policy intelligence</p>
        <h1 className="mt-2 text-3xl font-semibold tracking-[-0.04em] sm:text-4xl">Find configuration collisions</h1>
        <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-600 dark:text-slate-300">Compare settings across policy scopes and identify values that compete for the same target.</p>
      </header>

      {/* Stats bar */}
      {stats && (
        <div className="grid grid-cols-1 gap-px bg-slate-200 sm:grid-cols-2 lg:grid-cols-4 dark:bg-white/10">
          <StatCard index="01" label="Overlapping Settings" value={stats.totalOverlapping} />
          <StatCard index="02" label="Conflicting" value={stats.conflictCount} accent="red" />
          <StatCard index="03" label="Matching" value={stats.matchingCount} accent="green" />
          <StatCard index="04" label="Affected Policies" value={stats.affectedPolicies} />
        </div>
      )}

      {/* Scope selector */}
      <section className="space-y-5 border border-slate-200 bg-white p-5 dark:border-white/10 dark:bg-[#121b19] sm:p-6">
        <div><p className="text-xs font-semibold uppercase tracking-[0.15em] text-slate-500 dark:text-slate-400">Analysis scope</p><h2 className="mt-1 text-lg font-semibold">Choose what to compare</h2></div>

        {/* Scope mode toggle */}
        <div className="inline-flex max-w-full overflow-x-auto rounded-md border border-slate-200 bg-[#f3f5f2] p-1 dark:border-white/10 dark:bg-[#0c1211]">
          {([
            { key: 'all', label: 'All policies' },
            { key: 'group', label: 'By group' },
            { key: 'policy', label: 'By policy' },
          ] as const).map((opt) => (
            <button
              key={opt.key}
              onClick={() => { setScopeMode(opt.key); setConflicts(null); setStats(null) }}
              className={`px-4 py-2 text-sm font-medium rounded-md transition-colors ${
                scopeMode === opt.key
                  ? 'bg-[#16332f] text-white dark:bg-[#d9f99d] dark:text-[#16332f]'
                  : 'text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white'
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>

        {/* Group picker */}
        {scopeMode === 'group' && (
          <>
            <div className="space-y-2">
              <input
                type="text"
                value={groupFilter}
                onChange={(e) => setGroupFilter(e.target.value)}
                placeholder="Filter groups…"
                className="w-full max-w-md rounded-md border border-slate-300 bg-[#f8faf7] px-4 py-2 text-sm placeholder-slate-400 focus:border-[#147d72] dark:border-white/10 dark:bg-white/5"
              />
              <div className="max-h-48 overflow-y-auto border border-gray-200 dark:border-gray-700 rounded-lg divide-y divide-gray-100 dark:divide-gray-700/50">
                {/* Special targets */}
                {(!groupFilter.trim() || 'all users'.includes(groupFilter.toLowerCase())) && (
                  <button
                    onClick={() => setSelectedGroupId('all_users')}
                    className={`w-full text-left px-4 py-2.5 text-sm transition-colors ${
                      selectedGroupId === 'all_users'
                        ? 'bg-teal-50 text-teal-700 dark:bg-teal-900/30 dark:text-teal-300 font-medium'
                        : 'hover:bg-gray-50 dark:hover:bg-gray-700/30'
                    }`}
                  >
                    <span className="mr-1.5">👥</span> All Users
                  </button>
                )}
                {(!groupFilter.trim() || 'all devices'.includes(groupFilter.toLowerCase())) && (
                  <button
                    onClick={() => setSelectedGroupId('all_devices')}
                    className={`w-full text-left px-4 py-2.5 text-sm transition-colors ${
                      selectedGroupId === 'all_devices'
                        ? 'bg-teal-50 text-teal-700 dark:bg-teal-900/30 dark:text-teal-300 font-medium'
                        : 'hover:bg-gray-50 dark:hover:bg-gray-700/30'
                    }`}
                  >
                    <span className="mr-1.5">💻</span> All Devices
                  </button>
                )}
                {/* Regular groups */}
                {filteredGroups.slice(0, 50).map((g) => (
                  <button
                    key={g.id}
                    onClick={() => setSelectedGroupId(g.id)}
                    className={`w-full text-left px-4 py-2.5 text-sm transition-colors ${
                      selectedGroupId === g.id
                        ? 'bg-teal-50 text-teal-700 dark:bg-teal-900/30 dark:text-teal-300 font-medium'
                        : 'hover:bg-gray-50 dark:hover:bg-gray-700/30'
                    }`}
                  >
                    {g.displayName}
                  </button>
                ))}
                {filteredGroups.length === 0 && groupFilter.trim() && !('all users'.includes(groupFilter.toLowerCase()) || 'all devices'.includes(groupFilter.toLowerCase())) && (
                  <p className="text-sm text-gray-400 dark:text-gray-500 text-center py-4">No groups match</p>
                )}
              </div>
            </div>
            {selectedGroupId && !isSpecialTarget && (
              <div className="flex items-center gap-5">
                <label className="flex items-center gap-2 cursor-pointer select-none">
                  <input type="checkbox" checked={includeAllUsers} onChange={(e) => setIncludeAllUsers(e.target.checked)} className="h-4 w-4 rounded border-gray-300 text-[#147d72] focus:ring-[#147d72] dark:border-gray-600" />
                  <span className="text-sm text-gray-600 dark:text-gray-300">Include All Users</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer select-none">
                  <input type="checkbox" checked={includeAllDevices} onChange={(e) => setIncludeAllDevices(e.target.checked)} className="h-4 w-4 rounded border-gray-300 text-[#147d72] focus:ring-[#147d72] dark:border-gray-600" />
                  <span className="text-sm text-gray-600 dark:text-gray-300">Include All Devices</span>
                </label>
              </div>
            )}
          </>
        )}

        {/* Policy picker */}
        {scopeMode === 'policy' && (
          <div className="space-y-2">
            <input
              type="text"
              value={policyFilter}
              onChange={(e) => setPolicyFilter(e.target.value)}
              placeholder="Filter policies…"
              className="w-full max-w-md rounded-md border border-slate-300 bg-[#f8faf7] px-4 py-2 text-sm placeholder-slate-400 focus:border-[#147d72] dark:border-white/10 dark:bg-white/5"
            />
            <div className="max-h-48 overflow-y-auto border border-gray-200 dark:border-gray-700 rounded-lg divide-y divide-gray-100 dark:divide-gray-700/50">
              {filteredPolicies.slice(0, 50).map((p) => {
                const typeInfo = POLICY_TYPES.find((t) => t.key === p.policyType)
                return (
                  <button
                    key={p.id}
                    onClick={() => setSelectedPolicyId(p.id)}
                    className={`w-full text-left px-4 py-2.5 text-sm transition-colors ${
                      selectedPolicyId === p.id
                        ? 'bg-teal-50 text-teal-700 dark:bg-teal-900/30 dark:text-teal-300 font-medium'
                        : 'hover:bg-gray-50 dark:hover:bg-gray-700/30'
                    }`}
                  >
                    <span>{p.displayName}</span>
                    <span className="ml-2 text-xs text-gray-400">{typeInfo?.icon} {typeInfo?.label}</span>
                  </button>
                )
              })}
              {filteredPolicies.length === 0 && (
                <p className="text-sm text-gray-400 dark:text-gray-500 text-center py-4">No policies match</p>
              )}
            </div>
          </div>
        )}

        {/* Loading indicator */}
        {availablePlatforms.length > 0 && (
          <div className="space-y-2">
            <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Operating systems</p>
            <div className="flex flex-wrap gap-2">
              <button
                onClick={() => setSelectedPlatforms([])}
                className={`px-3 py-1.5 text-sm rounded-lg border transition-colors ${
                  selectedPlatforms.length === 0
                    ? 'border-[#147d72] bg-[#147d72] text-white'
                    : 'border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-600 dark:text-gray-300'
                }`}
              >
                All OS
              </button>
              {availablePlatforms.map((option) => {
                const selected = selectedPlatforms.includes(option.key)
                return (
                  <button
                    key={option.key}
                    onClick={() => setSelectedPlatforms((prev) => (
                      prev.includes(option.key)
                        ? prev.filter((key) => key !== option.key)
                        : [...prev, option.key]
                    ))}
                    className={`px-3 py-1.5 text-sm rounded-lg border transition-colors ${
                      selected
                        ? 'border-[#147d72] bg-[#147d72] text-white'
                        : 'border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-600 dark:text-gray-300'
                    }`}
                  >
                    {option.label}
                  </button>
                )
              })}
            </div>
          </div>
        )}

        {/* Loading indicator */}
        {loading && (
          <div className="flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400">
            <Spinner className="h-4 w-4" />
            Analysing{scopeLabel ? ` "${scopeLabel}"` : ''}…
          </div>
        )}
        {scopeLabel && !loading && (
          <p className="text-xs text-gray-400 dark:text-gray-500">
            Showing overlaps for: <span className="font-medium text-gray-600 dark:text-gray-300">{scopeLabel}</span>
          </p>
        )}
      </section>

      {/* Result filter controls */}
      {hasAnalyzed && (
        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
          {/* Filter chips */}
          <div className="inline-flex rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 p-1">
            {([
              { key: 'all', label: 'All Overlaps' },
              { key: 'conflicts', label: 'Conflicting Only' },
              { key: 'matching', label: 'Matching Only' },
            ] as const).map((chip) => (
              <button
                key={chip.key}
                onClick={() => setFilterMode(chip.key)}
                className={`px-3 py-1.5 text-sm font-medium rounded-md transition-colors ${
                  filterMode === chip.key
                    ? 'bg-[#16332f] text-white dark:bg-[#d9f99d] dark:text-[#16332f]'
                    : 'text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white'
                }`}
              >
                {chip.label}
              </button>
            ))}
          </div>

          {/* Search */}
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter by setting or policy name…"
            className="min-w-0 flex-1 rounded-md border border-slate-300 bg-white px-4 py-2 text-sm placeholder-slate-400 focus:border-[#147d72] dark:border-white/10 dark:bg-white/5"
          />
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 px-4 py-3 rounded-lg text-sm">
          {error}
        </div>
      )}

      {/* Empty states */}
      {!hasAnalyzed && !loading && scopeMode !== 'all' && (
        <div className="text-center py-16 text-gray-400 dark:text-gray-500">
          <p className="text-lg mb-2">👆</p>
          <p className="text-sm">
            {scopeMode === 'group' ? 'Select a group to analyse its overlapping settings' : 'Select a policy to find its overlapping settings'}
          </p>
        </div>
      )}

      {loading && (
        <div className="flex flex-col items-center justify-center py-16 gap-3 text-gray-400 dark:text-gray-500">
          <Spinner className="h-8 w-8 text-[#147d72]" />
          <p className="text-sm">Analysing{scopeLabel ? ` "${scopeLabel}"` : ' all policies'}…</p>
        </div>
      )}

      {hasAnalyzed && filtered.length === 0 && !loading && (
        <div className="text-center py-16 text-gray-400 dark:text-gray-500">
          <p className="text-lg mb-2">✅</p>
          <p className="text-sm">
            {search || filterMode !== 'all'
              ? 'No results match your filters'
              : 'No overlapping settings detected across your policies'}
          </p>
        </div>
      )}

      {/* Results */}
      {hasAnalyzed && filtered.length > 0 && (
        <div className="overflow-hidden border border-slate-200 bg-white dark:border-white/10 dark:bg-[#121b19]">
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
            <h2 className="text-lg font-semibold">Overlapping settings</h2>
            <span className="text-sm text-slate-600 dark:text-slate-300">{filtered.length} results</span>
          </div>

          <div className="divide-y divide-gray-100 dark:divide-gray-700/50">
            {filtered.map((item) => (
              <div key={item.settingKey} className="overflow-hidden">
                {/* Row header */}
                <button
                  onClick={() => toggleRow(item.settingKey)}
                  className="w-full text-left px-6 py-4 hover:bg-gray-50 dark:hover:bg-gray-700/20 transition-colors"
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <span className="flex-shrink-0 text-xs text-slate-600 dark:text-slate-300">{expandedRows.has(item.settingKey) ? '▾' : '▸'}</span>
                    <div className="flex-1 min-w-0 overflow-hidden">
                      <p className="text-sm font-medium truncate">{friendlySettingName(item.settingLabel || item.settingKey)}</p>
                      <p className="mt-0.5 truncate text-xs text-slate-600 dark:text-slate-300">
                        {formatSettingPath(item.settingKey)}
                      </p>
                    </div>
                    <span className="flex-shrink-0 whitespace-nowrap text-xs text-slate-600 dark:text-slate-300">
                      {item.policies.length} policies
                    </span>
                    <span
                      className={`inline-flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded flex-shrink-0 whitespace-nowrap ${
                        item.hasDifferentValues
                          ? 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300'
                          : 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300'
                      }`}
                    >
                      {item.hasDifferentValues ? '✕ Conflict' : '✓ Matching'}
                    </span>
                  </div>
                </button>

                {/* Expanded detail */}
                {expandedRows.has(item.settingKey) && (
                  <div className="px-6 pb-4 ml-6 overflow-hidden">
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                      {item.policies.map((p) => (
                        <div
                          key={p.policyId}
                          className={`rounded-lg border p-4 overflow-hidden ${
                            item.hasDifferentValues
                              ? 'border-red-200 dark:border-red-800 bg-red-50/50 dark:bg-red-900/10'
                              : 'border-green-200 dark:border-green-800 bg-green-50/50 dark:bg-green-900/10'
                          }`}
                        >
                          <p className="text-sm font-medium truncate" title={p.policyName}>{p.policyName}</p>
                          <p className="text-xs text-gray-400 dark:text-gray-500 mt-0.5 truncate">{policyTypeLabel(p.policyType)}</p>
                          <div className="mt-2 overflow-hidden">
                            <div className="flex items-start gap-1.5">
                              <span className={`flex-shrink-0 mt-0.5 ${item.hasDifferentValues ? 'text-red-500' : 'text-green-500'}`}>
                                {item.hasDifferentValues ? '✕' : '✓'}
                              </span>
                              <div className="min-w-0 overflow-hidden">
                                <p className="text-sm font-medium break-words whitespace-pre-line">
                                  {formatDisplayValue(p.valueDisplay, p.value)}
                                </p>
                                {p.value !== null && p.value !== undefined && String(p.value) !== p.valueDisplay && !looksLikeInternalGraphValue(String(p.value)) && (
                                  <p className="text-xs text-gray-400 dark:text-gray-500 font-mono mt-0.5 break-all">
                                    Raw: {typeof p.value === 'object' ? JSON.stringify(p.value) : String(p.value)}
                                  </p>
                                )}
                              </div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

/** Convert camelCase/PascalCase setting keys to readable names */
function friendlySettingName(name: string): string {
  const compact = name.replace(/_/g, '').toLowerCase()
  if (FRIENDLY_SETTING_SEGMENTS[compact]) return FRIENDLY_SETTING_SEGMENTS[compact]
  // If it already looks readable (has spaces), return as-is
  if (name.includes(' ')) return name
  // Split camelCase/PascalCase, handle acronyms
  return name
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .replace(/^./, (c) => c.toUpperCase())
    .replace(/_/g, ' ')
}

/** Format the display value, showing English name with raw value in brackets if different */
function formatDisplayValue(displayValue: string | undefined, rawValue: unknown): string {
  const display = displayValue || formatRawValue(rawValue)
  return display
}

function formatSettingPath(settingKey: string): string {
  const [prefix, rawPath] = settingKey.split(':', 2)
  if (!rawPath) return friendlySettingName(settingKey)

  if (prefix === 'settingsCatalog') {
    return formatSettingsCatalogPath(rawPath)
  }

  const exactRawLeaf = rawPath.includes('|') ? rawPath.split('|').pop() || rawPath : rawPath
  return `${friendlySettingName(prefix)} > ${friendlySettingName(exactRawLeaf)}`
}

function formatSettingsCatalogPath(rawPath: string): string {
  if (rawPath.includes('/')) {
    return rawPath
      .split('/')
      .filter(Boolean)
      .map((part) => friendlySettingName(part.replace(/^\.\//, '')))
      .join(' / ')
  }

  const knownPrefix = 'device_vendor_msft_policy_config_'
  if (!rawPath.startsWith(knownPrefix)) {
    return `Settings Catalog > ${friendlySettingName(rawPath)}`
  }

  const remainder = rawPath.slice(knownPrefix.length)
  const [category, ...rest] = remainder.split('_')
  return `Settings Catalog > ${friendlySettingName(category)} > ${friendlySettingName(rest.join('_'))}`
}

function normalizePlatformKeys(platform: string | null | undefined): PlatformFilter[] {
  const raw = (platform || '').trim().toLowerCase()
  if (!raw) return ['unknown']

  const keys = new Set<PlatformFilter>()
  if (raw.includes('windows')) keys.add('windows')
  if (raw.includes('macos') || raw.includes('mac')) keys.add('macos')
  if (raw.includes('ios') || raw.includes('iphone') || raw.includes('ipad')) keys.add('ios')
  if (raw.includes('android')) keys.add('android')
  if (raw.includes('linux')) keys.add('linux')

  return keys.size > 0 ? [...keys] : ['unknown']
}

function looksLikeInternalGraphValue(value: string): boolean {
  return value.includes('device_vendor_msft_') || value.startsWith('#microsoft.graph.')
}

function formatRawValue(value: unknown): string {
  if (value === null || value === undefined) return 'Not Configured'
  if (typeof value === 'boolean') return value ? 'Enabled' : 'Disabled'
  if (typeof value === 'string' || typeof value === 'number') return String(value)
  return JSON.stringify(value)
}
