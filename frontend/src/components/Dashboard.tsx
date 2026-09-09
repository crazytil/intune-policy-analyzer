import type { Policy, Group } from '../types'
import { POLICY_TYPES } from '../types'

interface DashboardProps {
  policies: Policy[]
  groups: Group[]
  loading: boolean
  onRefresh: () => void
  onOpenConflicts: () => void
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

function StatCard({ index, label, value, sub, accent = false }: { index: string; label: string; value: string | number; sub?: string; accent?: boolean }) {
  return (
    <div className={`relative overflow-hidden border-t-2 p-5 sm:p-6 ${accent ? 'border-[#147d72] bg-[#16332f] text-white dark:bg-[#d9f99d] dark:text-[#16332f]' : 'border-slate-300 bg-white dark:border-slate-700 dark:bg-[#121b19]'}`}>
      <div className="flex items-center justify-between gap-3">
        <p className={`text-xs font-semibold uppercase tracking-[0.14em] ${accent ? 'text-white/65 dark:text-[#16332f]/60' : 'text-slate-500 dark:text-slate-400'}`}>{label}</p>
        <span aria-hidden="true" className={`font-mono text-[10px] ${accent ? 'text-white/70 dark:text-[#16332f]/70' : 'text-slate-500 dark:text-slate-400'}`}>{index}</span>
      </div>
      <p className="mt-5 text-4xl font-semibold tracking-[-0.04em] tabular-nums">{value}</p>
      {sub && <p className={`mt-2 text-sm ${accent ? 'text-white/65 dark:text-[#16332f]/65' : 'text-slate-500 dark:text-slate-400'}`}>{sub}</p>}
    </div>
  )
}

export default function Dashboard({ policies, groups, loading, onRefresh, onOpenConflicts, loadedAt, fromCache }: DashboardProps) {
  const loaded = policies.length > 0

  const typeCounts = POLICY_TYPES.map((pt) => {
    const count = policies.filter((p) => p.policyType === pt.key).length
    return { ...pt, count }
  }).filter((t) => t.count > 0)

  const groupIds = new Set<string>()
  let assignmentCount = 0
  for (const policy of policies) {
    assignmentCount += policy.assignments.length
    for (const assignment of policy.assignments) {
      const a = assignment as { target?: { groupId?: string } }
      if (a.target?.groupId) {
        groupIds.add(a.target.groupId)
      }
    }
  }

  return (
    <div className="space-y-8">
      <header className="flex flex-col justify-between gap-5 sm:flex-row sm:items-end">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[#147d72] dark:text-[#6ee7d8]">Tenant overview</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-[-0.04em] sm:text-4xl">Configuration at a glance</h1>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-600 dark:text-slate-300">Inventory, assignment coverage, and policy distribution from the connected tenant.</p>
        </div>
        {loaded && (
          <button
            onClick={onRefresh}
            disabled={loading}
            className="inline-flex h-10 items-center justify-center gap-2 self-start rounded-md border border-slate-300 bg-white px-4 text-sm font-semibold text-slate-700 transition hover:-translate-y-0.5 hover:border-slate-400 hover:text-slate-950 active:translate-y-0 disabled:opacity-60 dark:border-white/15 dark:bg-white/5 dark:text-slate-200 dark:hover:bg-white/10"
          >
            {loading ? <Spinner /> : <span aria-hidden="true">↻</span>}
            {loading ? 'Refreshing…' : 'Refresh tenant'}
          </button>
        )}
      </header>

      <div className="grid grid-cols-1 gap-px bg-slate-200 sm:grid-cols-2 lg:grid-cols-4 dark:bg-white/10">
        <StatCard
          index="01"
          label="Total Policies"
          value={loaded ? policies.length : '—'}
          sub={loaded ? `${typeCounts.length} types` : 'Not loaded'}
          accent
        />
        <StatCard
          index="02"
          label="Groups in Tenant"
          value={groups.length > 0 ? groups.length : '—'}
          sub={loaded ? `${groupIds.size} with assignments` : 'Not loaded'}
        />
        <StatCard
          index="03"
          label="Assignments"
          value={loaded ? assignmentCount : '—'}
          sub="Across loaded policies"
        />
        <StatCard
          index="04"
          label="Optimisation Score"
          value="—"
          sub="Analysis coming soon"
        />
      </div>

      {loading && !loaded && (
        <div className="border border-slate-200 bg-white p-8 dark:border-white/10 dark:bg-[#121b19]" aria-live="polite">
          <div className="flex items-center gap-3 text-sm font-semibold">
            <Spinner />
            Reading tenant configuration…
          </div>
          <div className="mt-8 space-y-4 animate-pulse">
            {[82, 64, 49, 35].map((width) => <div key={width} className="h-3 bg-slate-100 dark:bg-white/10" style={{ width: `${width}%` }} />)}
          </div>
        </div>
      )}

      {!loading && !loaded && (
        <div className="grid min-h-72 place-items-center border border-dashed border-slate-300 bg-white/50 px-6 py-16 text-center dark:border-white/15 dark:bg-white/[0.025]">
          <div className="max-w-md">
            <span className="mx-auto grid h-12 w-12 place-items-center rounded-xl bg-[#16332f] font-mono text-sm text-white dark:bg-[#d9f99d] dark:text-[#16332f]">IP</span>
            <h2 className="mt-5 text-xl font-semibold">No tenant data loaded</h2>
            <p className="mt-2 text-sm leading-6 text-slate-500 dark:text-slate-400">Refresh the connection to read policies and groups from Microsoft Graph.</p>
            <button onClick={onRefresh} className="mt-6 rounded-md bg-[#16332f] px-5 py-2.5 text-sm font-semibold text-white transition hover:-translate-y-0.5 hover:bg-[#214942] active:translate-y-0 dark:bg-[#d9f99d] dark:text-[#16332f]">Load tenant data</button>
          </div>
        </div>
      )}

      {loaded && (
        <div className="grid gap-6 lg:grid-cols-[minmax(0,1.6fr)_minmax(18rem,0.8fr)]">
          <section className="overflow-hidden bg-white dark:bg-[#121b19]">
            <div className="flex items-end justify-between border-b border-slate-200 px-5 py-5 sm:px-6 dark:border-white/10">
              <div><h2 className="text-lg font-semibold tracking-tight">Policy distribution</h2><p className="mt-1 text-xs text-slate-500 dark:text-slate-400">Loaded configuration by policy family</p></div>
              <span className="font-mono text-xs text-slate-600 dark:text-slate-300">COUNT</span>
            </div>
            <div className="divide-y divide-slate-100 dark:divide-white/[0.06]">
              {typeCounts.map((type) => (
                <div key={type.key} className="grid grid-cols-[2rem_minmax(0,1fr)_3rem] items-center gap-4 px-5 py-3.5 transition hover:bg-[#f7f9f6] sm:px-6 dark:hover:bg-white/[0.03]">
                  <span className="grid h-8 w-8 place-items-center rounded-md bg-slate-100 font-mono text-[10px] font-bold text-slate-600 dark:bg-white/10 dark:text-slate-300">{type.icon}</span>
                  <div className="min-w-0">
                    <div className="mb-2 flex items-center justify-between gap-3"><span className="truncate text-sm font-medium">{type.label}</span><span className="text-xs text-slate-600 dark:text-slate-300">{Math.round((type.count / policies.length) * 100)}%</span></div>
                    <div className="h-1 bg-slate-100 dark:bg-white/10"><div className="h-full bg-[#147d72] dark:bg-[#6ee7d8]" style={{ width: `${(type.count / policies.length) * 100}%` }} /></div>
                  </div>
                  <span className="text-right font-mono text-sm font-semibold tabular-nums">{type.count}</span>
                </div>
              ))}
            </div>
          </section>

          <aside className="space-y-4">
            <div className="bg-[#d9f99d] p-6 text-[#16332f] dark:bg-[#c9ed89]">
              <p className="text-xs font-bold uppercase tracking-[0.16em]">Next review</p>
              <h2 className="mt-4 text-2xl font-semibold tracking-[-0.035em]">Check policy overlap</h2>
              <p className="mt-3 text-sm leading-6 text-[#31534d]">Run conflict analysis to compare configured values across policies that share a target.</p>
              <button onClick={onOpenConflicts} className="mt-7 w-full border-t border-[#16332f]/15 pt-4 text-left text-xs font-bold transition hover:translate-x-1">Open conflict analysis <span aria-hidden="true">→</span></button>
            </div>
            <div className="border border-slate-200 bg-white p-5 dark:border-white/10 dark:bg-[#121b19]">
              <p className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-500 dark:text-slate-400">Data source</p>
              <div className="mt-4 flex items-center gap-3"><span className="h-2.5 w-2.5 rounded-full bg-emerald-500 shadow-[0_0_0_4px_rgba(16,185,129,0.12)]" /><div><p className="text-sm font-semibold">Microsoft Graph</p><p className="text-xs text-slate-500 dark:text-slate-400">{fromCache ? 'Showing cached data; refreshing in background' : 'Live tenant snapshot'}</p></div></div>
              {loadedAt && <p className="mt-4 border-t border-slate-100 pt-4 text-xs text-slate-600 dark:border-white/10 dark:text-slate-300">Updated {timeAgo(loadedAt)}</p>}
            </div>
          </aside>
        </div>
      )}
    </div>
  )
}
