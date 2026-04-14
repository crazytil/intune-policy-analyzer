import { useState, useMemo, useCallback } from 'react'
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

function Spinner({ className = 'h-5 w-5' }: { className?: string }) {
  return (
    <svg className={`animate-spin ${className}`} viewBox="0 0 24 24" fill="none">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
    </svg>
  )
}

function StatCard({ label, value, icon, accent }: { label: string; value: number | string; icon: string; accent?: string }) {
  const accentClass = accent === 'red'
    ? 'text-red-600 dark:text-red-400'
    : accent === 'green'
      ? 'text-green-600 dark:text-green-400'
      : accent === 'amber'
        ? 'text-amber-600 dark:text-amber-400'
        : ''
  return (
    <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-6">
      <p className="text-sm font-medium text-gray-500 dark:text-gray-400">{icon} {label}</p>
      <p className={`mt-2 text-3xl font-bold tracking-tight ${accentClass}`}>{value}</p>
    </div>
  )
}

export default function ConflictAnalyzer({ policies, groups }: ConflictAnalyzerProps) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [conflicts, setConflicts] = useState<ConflictItem[] | null>(null)
  const [stats, setStats] = useState<ConflictStats | null>(null)
  const [filterMode, setFilterMode] = useState<FilterMode>('all')
  const [search, setSearch] = useState('')
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set())

  // Scope selection
  const [scopeMode, setScopeMode] = useState<ScopeMode>('all')
  const [selectedGroupId, setSelectedGroupId] = useState<string>('')
  const [selectedPolicyId, setSelectedPolicyId] = useState<string>('')
  const [groupFilter, setGroupFilter] = useState('')
  const [policyFilter, setPolicyFilter] = useState('')

  const filteredGroups = groupFilter.trim()
    ? groups.filter((g) => g.displayName.toLowerCase().includes(groupFilter.toLowerCase()))
    : groups

  const filteredPolicies = policyFilter.trim()
    ? policies.filter((p) => p.displayName.toLowerCase().includes(policyFilter.toLowerCase()))
    : policies

  const isSpecialTarget = selectedGroupId === 'all_users' || selectedGroupId === 'all_devices'

  const scopeLabel = scopeMode === 'group'
    ? (selectedGroupId === 'all_users' ? 'All Users'
      : selectedGroupId === 'all_devices' ? 'All Devices'
      : groups.find((g) => g.id === selectedGroupId)?.displayName)
    : scopeMode === 'policy'
      ? policies.find((p) => p.id === selectedPolicyId)?.displayName
      : null

  const canAnalyze =
    scopeMode === 'all' ||
    (scopeMode === 'group' && selectedGroupId) ||
    (scopeMode === 'policy' && selectedPolicyId)

  const handleAnalyze = useCallback(async () => {
    setLoading(true)
    setError(null)
    setExpandedRows(new Set())
    try {
      let result
      if (scopeMode === 'group' && isSpecialTarget) {
        result = await analyzeConflictsForTarget(selectedGroupId as 'all_users' | 'all_devices')
      } else if (scopeMode === 'group' && selectedGroupId) {
        result = await analyzeConflictsForGroup(selectedGroupId)
      } else if (scopeMode === 'policy' && selectedPolicyId) {
        result = await analyzeConflictsForPolicy(selectedPolicyId)
      } else {
        result = await analyzeConflicts()
      }
      setConflicts(result.conflicts)
      setStats(result.stats)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Analysis failed')
    } finally {
      setLoading(false)
    }
  }, [scopeMode, selectedGroupId, selectedPolicyId, isSpecialTarget])

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
    <div className="space-y-6">
      {/* Stats bar */}
      {stats && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard icon="🔗" label="Overlapping Settings" value={stats.totalOverlapping} />
          <StatCard icon="⚠️" label="Conflicting" value={stats.conflictCount} accent="red" />
          <StatCard icon="✅" label="Matching" value={stats.matchingCount} accent="green" />
          <StatCard icon="📦" label="Affected Policies" value={stats.affectedPolicies} />
        </div>
      )}

      {/* Scope selector */}
      <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-5 space-y-4">
        <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Analyze scope</p>

        {/* Scope mode toggle */}
        <div className="inline-flex rounded-lg border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900 p-1">
          {([
            { key: 'all', label: '🌐 All Policies' },
            { key: 'group', label: '👥 By Group' },
            { key: 'policy', label: '📋 By Policy' },
          ] as const).map((opt) => (
            <button
              key={opt.key}
              onClick={() => { setScopeMode(opt.key); setConflicts(null); setStats(null) }}
              className={`px-4 py-2 text-sm font-medium rounded-md transition-colors ${
                scopeMode === opt.key
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200'
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>

        {/* Group picker */}
        {scopeMode === 'group' && (
          <div className="space-y-2">
            <input
              type="text"
              value={groupFilter}
              onChange={(e) => setGroupFilter(e.target.value)}
              placeholder="Filter groups…"
              className="w-full max-w-md px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 placeholder-gray-400"
            />
            <div className="max-h-48 overflow-y-auto border border-gray-200 dark:border-gray-700 rounded-lg divide-y divide-gray-100 dark:divide-gray-700/50">
              {/* Special targets */}
              {(!groupFilter.trim() || 'all users'.includes(groupFilter.toLowerCase())) && (
                <button
                  onClick={() => setSelectedGroupId('all_users')}
                  className={`w-full text-left px-4 py-2.5 text-sm transition-colors ${
                    selectedGroupId === 'all_users'
                      ? 'bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 font-medium'
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
                      ? 'bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 font-medium'
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
                      ? 'bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 font-medium'
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
        )}

        {/* Policy picker */}
        {scopeMode === 'policy' && (
          <div className="space-y-2">
            <input
              type="text"
              value={policyFilter}
              onChange={(e) => setPolicyFilter(e.target.value)}
              placeholder="Filter policies…"
              className="w-full max-w-md px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 placeholder-gray-400"
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
                        ? 'bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 font-medium'
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

        {/* Analyze button + scope label */}
        <div className="flex items-center gap-3">
          <button
            onClick={handleAnalyze}
            disabled={loading || !canAnalyze}
            className="inline-flex items-center gap-2 px-5 py-2.5 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-60 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? (
              <>
                <Spinner className="h-4 w-4" />
                Analyzing…
              </>
            ) : (
              hasAnalyzed ? '↻ Re-analyze' : 'Analyze Overlapping Settings'
            )}
          </button>
          {scopeLabel && (
            <span className="text-sm text-gray-500 dark:text-gray-400">
              Scope: <span className="font-medium text-gray-700 dark:text-gray-200">{scopeLabel}</span>
            </span>
          )}
        </div>
      </div>

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
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200'
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
            className="flex-1 min-w-0 px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-blue-400 placeholder-gray-400"
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
      {!hasAnalyzed && !loading && (
        <div className="text-center py-16 text-gray-400 dark:text-gray-500">
          <p className="text-lg mb-2">🔍</p>
          <p className="text-sm">Click &ldquo;Analyze Overlapping Settings&rdquo; to scan all policies for overlapping settings</p>
          {policies.length === 0 && (
            <p className="text-xs mt-2 text-gray-300 dark:text-gray-600">Load policies from the Dashboard first</p>
          )}
        </div>
      )}

      {loading && !hasAnalyzed && (
        <div className="flex flex-col items-center justify-center py-16 gap-3 text-gray-400 dark:text-gray-500">
          <Spinner className="h-8 w-8 text-blue-500" />
          <p className="text-sm">Analyzing policies…</p>
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
        <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
            <h2 className="text-lg font-semibold">Overlapping Settings</h2>
            <span className="text-sm text-gray-400 dark:text-gray-500">{filtered.length} results</span>
          </div>

          <div className="divide-y divide-gray-100 dark:divide-gray-700/50">
            {filtered.map((item) => (
              <div key={item.settingKey}>
                {/* Row header */}
                <button
                  onClick={() => toggleRow(item.settingKey)}
                  className="w-full text-left px-6 py-4 hover:bg-gray-50 dark:hover:bg-gray-700/20 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <span className="text-xs text-gray-400">{expandedRows.has(item.settingKey) ? '▾' : '▸'}</span>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate">{item.settingLabel || item.settingKey}</p>
                      {item.settingLabel && item.settingLabel !== item.settingKey && (
                        <p className="text-xs text-gray-400 dark:text-gray-500 font-mono truncate mt-0.5">{item.settingKey}</p>
                      )}
                    </div>
                    <span className="text-xs text-gray-400 dark:text-gray-500 flex-shrink-0">
                      {item.policies.length} policies
                    </span>
                    <span
                      className={`inline-flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded flex-shrink-0 ${
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
                  <div className="px-6 pb-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 ml-6">
                    {item.policies.map((p) => (
                      <div
                        key={p.policyId}
                        className={`rounded-lg border p-4 ${
                          item.hasDifferentValues
                            ? 'border-red-200 dark:border-red-800 bg-red-50/50 dark:bg-red-900/10'
                            : 'border-green-200 dark:border-green-800 bg-green-50/50 dark:bg-green-900/10'
                        }`}
                      >
                        <p className="text-sm font-medium truncate">{p.policyName}</p>
                        <p className="text-xs text-gray-400 dark:text-gray-500 mt-0.5">{policyTypeLabel(p.policyType)}</p>
                        <div className="mt-2">
                          <p className="text-sm font-medium">
                            <span className={`inline-block mr-1.5 ${item.hasDifferentValues ? 'text-red-500' : 'text-green-500'}`}>
                              {item.hasDifferentValues ? '✕' : '✓'}
                            </span>
                            {p.valueDisplay || formatFallbackValue(p.value)}
                          </p>
                        </div>
                      </div>
                    ))}
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

function formatFallbackValue(value: unknown): string {
  if (value === null || value === undefined) return 'Not Configured'
  if (typeof value === 'boolean') return value ? 'Enabled' : 'Disabled'
  if (typeof value === 'string' || typeof value === 'number') return String(value)
  return JSON.stringify(value)
}
