import { useState, useMemo } from 'react'
import type { Policy } from '../types'
import { POLICY_TYPES } from '../types'
import { analyzeConflicts } from '../services/api'
import type { ConflictItem, ConflictStats } from '../services/api'

interface ConflictAnalyzerProps {
  policies: Policy[]
}

type FilterMode = 'all' | 'conflicts' | 'duplicates'

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

function ValueDisplay({ value }: { value: unknown }) {
  if (value === null || value === undefined) return <span className="text-gray-400 italic">null</span>
  if (typeof value === 'boolean') return <span className="font-mono">{value ? 'true' : 'false'}</span>
  if (typeof value === 'string' || typeof value === 'number') return <span className="font-mono">{String(value)}</span>
  return (
    <pre className="text-xs bg-gray-50 dark:bg-gray-900 rounded p-2 overflow-x-auto max-h-32 text-gray-700 dark:text-gray-300">
      {JSON.stringify(value, null, 2)}
    </pre>
  )
}

export default function ConflictAnalyzer({ policies }: ConflictAnalyzerProps) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [conflicts, setConflicts] = useState<ConflictItem[] | null>(null)
  const [stats, setStats] = useState<ConflictStats | null>(null)
  const [filterMode, setFilterMode] = useState<FilterMode>('all')
  const [search, setSearch] = useState('')
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set())

  const handleAnalyze = async () => {
    setLoading(true)
    setError(null)
    setExpandedRows(new Set())
    try {
      const result = await analyzeConflicts()
      setConflicts(result.conflicts)
      setStats(result.stats)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Analysis failed')
    } finally {
      setLoading(false)
    }
  }

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
    if (filterMode === 'duplicates') items = items.filter((c) => !c.hasDifferentValues)
    if (search.trim()) {
      const q = search.toLowerCase()
      items = items.filter(
        (c) =>
          c.settingKey.toLowerCase().includes(q) ||
          c.settingLabel.toLowerCase().includes(q) ||
          c.policies.some((p) => p.policyName.toLowerCase().includes(q)),
      )
    }
    // Sort: conflicts first, then duplicates
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
          <StatCard icon="📊" label="Shared Settings" value={stats.totalSharedSettings} />
          <StatCard icon="⚠️" label="Conflicts" value={stats.conflictCount} accent="red" />
          <StatCard icon="📋" label="Duplicates" value={stats.duplicateCount} accent="amber" />
          <StatCard icon="📦" label="Affected Policies" value={stats.affectedPolicies} />
        </div>
      )}

      {/* Controls */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
        <button
          onClick={handleAnalyze}
          disabled={loading}
          className="inline-flex items-center gap-2 px-5 py-2.5 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-60 disabled:cursor-not-allowed transition-colors"
        >
          {loading ? (
            <>
              <Spinner className="h-4 w-4" />
              Analyzing…
            </>
          ) : (
            hasAnalyzed ? '↻ Re-analyze' : 'Start Analysis'
          )}
        </button>

        {hasAnalyzed && (
          <>
            {/* Filter chips */}
            <div className="inline-flex rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 p-1">
              {([
                { key: 'all', label: 'All' },
                { key: 'conflicts', label: 'Conflicts Only' },
                { key: 'duplicates', label: 'Duplicates Only' },
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
          </>
        )}
      </div>

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
          <p className="text-sm">Click &ldquo;Start Analysis&rdquo; to scan all policies for overlapping settings</p>
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
                      className={`inline-block text-xs font-medium px-2 py-0.5 rounded flex-shrink-0 ${
                        item.hasDifferentValues
                          ? 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300'
                          : 'bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300'
                      }`}
                    >
                      {item.hasDifferentValues ? 'Conflict' : 'Duplicate'}
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
                            : 'border-amber-200 dark:border-amber-800 bg-amber-50/50 dark:bg-amber-900/10'
                        }`}
                      >
                        <p className="text-sm font-medium truncate">{p.policyName}</p>
                        <p className="text-xs text-gray-400 dark:text-gray-500 mt-0.5">{policyTypeLabel(p.policyType)}</p>
                        <div className="mt-2 text-sm">
                          <span className="text-xs text-gray-400 dark:text-gray-500">Value: </span>
                          <ValueDisplay value={p.value} />
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
