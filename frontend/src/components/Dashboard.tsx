import type { Policy, Group } from '../types'
import { POLICY_TYPES } from '../types'

interface DashboardProps {
  policies: Policy[]
  groups: Group[]
  loading: boolean
  onRefresh: () => void
  loadedAt: number | null
  fromCache: boolean
}

function timeAgo(timestamp: number): string {
  const seconds = Math.floor((Date.now() - timestamp) / 1000)
  if (seconds < 60) return 'just now'
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ${minutes % 60}m ago`
  return new Date(timestamp).toLocaleString()
}

function Spinner() {
  return (
    <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24" fill="none">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
    </svg>
  )
}

function StatCard({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-6">
      <p className="text-sm font-medium text-gray-500 dark:text-gray-400">{label}</p>
      <p className="mt-2 text-3xl font-bold tracking-tight">{value}</p>
      {sub && <p className="mt-1 text-sm text-gray-400 dark:text-gray-500">{sub}</p>}
    </div>
  )
}

export default function Dashboard({ policies, groups, loading, onRefresh, loadedAt, fromCache }: DashboardProps) {
  const loaded = policies.length > 0

  const typeCounts = POLICY_TYPES.map((pt) => {
    const count = policies.filter((p) => p.policyType === pt.key).length
    return { ...pt, count }
  }).filter((t) => t.count > 0)

  const groupIds = new Set<string>()
  for (const policy of policies) {
    for (const assignment of policy.assignments) {
      const a = assignment as { target?: { groupId?: string } }
      if (a.target?.groupId) {
        groupIds.add(a.target.groupId)
      }
    }
  }

  return (
    <div className="space-y-6">
      {/* Summary cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Total Policies"
          value={loaded ? policies.length : '—'}
          sub={loaded ? `${typeCounts.length} types` : 'Not loaded'}
        />
        <StatCard
          label="Groups in Tenant"
          value={groups.length > 0 ? groups.length : '—'}
          sub={loaded ? `${groupIds.size} with assignments` : 'Not loaded'}
        />
        <StatCard
          label="Conflicts Found"
          value="—"
          sub="Run Conflict Analyzer"
        />
        <StatCard
          label="Optimization Score"
          value="—"
          sub="Coming soon"
        />
      </div>

      {/* Loading indicator */}
      {loading && !loaded && (
        <div className="flex justify-center">
          <div className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 text-white font-medium rounded-lg opacity-80">
            <Spinner />
            Loading policies and groups…
          </div>
        </div>
      )}

      {/* Cache status + Refresh button */}
      {loaded && (
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-sm text-gray-400 dark:text-gray-500">
            {fromCache && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-yellow-50 dark:bg-yellow-900/20 text-yellow-600 dark:text-yellow-400 text-xs font-medium rounded">
                ⚡ Cached
              </span>
            )}
            {loadedAt && (
              <span>
                {policies.length} policies · {groups.length} groups · Loaded {timeAgo(loadedAt)}
              </span>
            )}
          </div>
          <button
            onClick={onRefresh}
            disabled={loading}
            className="inline-flex items-center gap-2 px-4 py-2 text-sm bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-200 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600 disabled:opacity-60 transition-colors"
          >
            {loading ? <Spinner /> : '↻'}
            {loading ? 'Refreshing…' : 'Refresh All'}
          </button>
        </div>
      )}

      {/* Policy breakdown table */}
      {loaded && (
        <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
            <h2 className="text-lg font-semibold">Policies by Type</h2>
          </div>
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-100 dark:border-gray-700 text-left text-sm text-gray-500 dark:text-gray-400">
                <th className="px-6 py-3 font-medium">Type</th>
                <th className="px-6 py-3 font-medium text-right">Count</th>
              </tr>
            </thead>
            <tbody>
              {typeCounts.map((t) => (
                <tr
                  key={t.key}
                  className="border-b border-gray-50 dark:border-gray-700/50 hover:bg-gray-50 dark:hover:bg-gray-700/30 transition-colors"
                >
                  <td className="px-6 py-3">
                    <span className="mr-2">{t.icon}</span>
                    {t.label}
                  </td>
                  <td className="px-6 py-3 text-right font-mono">{t.count}</td>
                </tr>
              ))}
              <tr className="font-semibold bg-gray-50 dark:bg-gray-700/30">
                <td className="px-6 py-3">Total</td>
                <td className="px-6 py-3 text-right font-mono">{policies.length}</td>
              </tr>
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
