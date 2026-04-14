import { useEffect, useMemo, useState } from 'react'
import { analyzeOptimization } from '../services/api'
import type { OptimizationAnalysisResult } from '../types'
import { POLICY_TYPES } from '../types'

interface OptimizationProps {
  isReady: boolean
}

function Spinner({ className = 'h-5 w-5' }: { className?: string }) {
  return (
    <svg className={`animate-spin ${className}`} viewBox="0 0 24 24" fill="none">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
    </svg>
  )
}

function StatCard({ label, value, sub }: { label: string; value: number | string; sub: string }) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-6">
      <p className="text-sm font-medium text-gray-500 dark:text-gray-400">{label}</p>
      <p className="mt-2 text-3xl font-bold tracking-tight">{value}</p>
      <p className="mt-1 text-sm text-gray-400 dark:text-gray-500">{sub}</p>
    </div>
  )
}

function badgeClasses(type: 'consolidationCandidate' | 'fragmentationHotspot'): string {
  return type === 'consolidationCandidate'
    ? 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-900/20 dark:text-emerald-300 dark:border-emerald-800'
    : 'bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-900/20 dark:text-amber-300 dark:border-amber-800'
}

function recommendationLabel(type: 'consolidationCandidate' | 'fragmentationHotspot'): string {
  return type === 'consolidationCandidate' ? 'Consolidation Candidate' : 'Fragmentation Hotspot'
}

function policyTypeLabel(policyType: string): string {
  const info = POLICY_TYPES.find((item) => item.key === policyType)
  return info ? `${info.icon} ${info.label}` : policyType
}

export default function Optimization({ isReady }: OptimizationProps) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<OptimizationAnalysisResult | null>(null)
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [selectedPlatforms, setSelectedPlatforms] = useState<string[]>([])
  const [selectedDomain, setSelectedDomain] = useState('all')

  useEffect(() => {
    if (!isReady) return

    let cancelled = false

    async function load() {
      setLoading(true)
      setError(null)
      try {
        const next = await analyzeOptimization({
          platforms: selectedPlatforms.map((platform) => platform.toLowerCase()),
        })
        if (!cancelled) setResult(next)
      } catch (nextError) {
        if (!cancelled) {
          setError(nextError instanceof Error ? nextError.message : 'Failed to load optimisation findings')
        }
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    void load()
    return () => {
      cancelled = true
    }
  }, [isReady, selectedPlatforms])

  const domains = result?.summary.domains ?? []
  const platformOptions = result?.summary.platforms ?? []

  const visibleFindings = useMemo(() => {
    const findings = result?.findings ?? []
    return findings.filter((finding) => selectedDomain === 'all' || finding.domain === selectedDomain)
  }, [result, selectedDomain])

  const togglePlatform = (platform: string) => {
    setSelectedPlatforms((current) =>
      current.includes(platform)
        ? current.filter((value) => value !== platform)
        : [...current, platform],
    )
  }

  const toggleExpanded = (key: string) => {
    setExpanded((current) => {
      const next = new Set(current)
      next.has(key) ? next.delete(key) : next.add(key)
      return next
    })
  }

  if (!isReady) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-6 text-sm text-gray-500 dark:text-gray-400">
        Load policies first to analyse consolidation opportunities.
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {result && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard label="Findings" value={result.summary.totalFindings} sub="High-signal only" />
          <StatCard label="Consolidation" value={result.summary.consolidationCandidates} sub="Low-conflict merge candidates" />
          <StatCard label="Fragmentation" value={result.summary.fragmentationHotspots} sub="Same domain spread across too many policies" />
          <StatCard label="Domains" value={result.summary.domains.length} sub="Detected recommendation domains" />
        </div>
      )}

      <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-5 space-y-4">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Optimisation engine</p>
            <h2 className="text-lg font-semibold mt-1">Read-only consolidation recommendations</h2>
          </div>
          <button
            onClick={() => setSelectedPlatforms([])}
            className="px-3 py-2 text-sm rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700/40 transition-colors"
          >
            Clear platform filters
          </button>
        </div>

        <div className="space-y-3">
          <div>
            <p className="text-xs font-medium uppercase tracking-wide text-gray-400 dark:text-gray-500 mb-2">Platforms</p>
            <div className="flex flex-wrap gap-2">
              {platformOptions.map((platform) => (
                <button
                  key={platform}
                  onClick={() => togglePlatform(platform)}
                  className={`px-3 py-1.5 text-sm rounded-full border transition-colors ${
                    selectedPlatforms.includes(platform)
                      ? 'bg-blue-600 text-white border-blue-600'
                      : 'border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700/40'
                  }`}
                >
                  {platform}
                </button>
              ))}
              {platformOptions.length === 0 && (
                <span className="text-sm text-gray-400 dark:text-gray-500">No platform recommendations yet</span>
              )}
            </div>
          </div>

          <div>
            <p className="text-xs font-medium uppercase tracking-wide text-gray-400 dark:text-gray-500 mb-2">Domain</p>
            <select
              value={selectedDomain}
              onChange={(event) => setSelectedDomain(event.target.value)}
              className="w-full max-w-sm px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="all">All detected domains</option>
              {domains.map((domain) => (
                <option key={domain} value={domain}>
                  {domain}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {loading && (
        <div className="flex justify-center">
          <div className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 text-white font-medium rounded-lg opacity-80">
            <Spinner />
            Analysing policy clusters…
          </div>
        </div>
      )}

      {error && (
        <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 px-4 py-3 rounded-lg text-sm">
          {error}
        </div>
      )}

      {!loading && !error && result && visibleFindings.length === 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-6 text-sm text-gray-500 dark:text-gray-400">
          No optimisation findings matched the current filters.
        </div>
      )}

      {!loading && !error && visibleFindings.map((finding) => {
        const key = `${finding.recommendationType}:${finding.domain}:${finding.audience}:${finding.platforms.join(',')}`
        const isExpanded = expanded.has(key)
        return (
          <div key={key} className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
            <button
              onClick={() => toggleExpanded(key)}
              className="w-full text-left px-5 py-5 hover:bg-gray-50 dark:hover:bg-gray-700/30 transition-colors"
            >
              <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                <div className="space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={`inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-medium ${badgeClasses(finding.recommendationType)}`}>
                      {recommendationLabel(finding.recommendationType)}
                    </span>
                    <span className="text-xs text-gray-400 dark:text-gray-500">{finding.domain}</span>
                    <span className="text-xs text-gray-400 dark:text-gray-500">•</span>
                    <span className="text-xs text-gray-400 dark:text-gray-500">{finding.platforms.join(', ')}</span>
                  </div>
                  <h3 className="text-lg font-semibold">{finding.title}</h3>
                  <p className="text-sm text-gray-500 dark:text-gray-400">{finding.summary}</p>
                  <p className="text-sm text-gray-500 dark:text-gray-400">{finding.audience}</p>
                </div>
                <div className="grid grid-cols-2 gap-3 text-sm min-w-[16rem]">
                  <div className="rounded-lg bg-gray-50 dark:bg-gray-900 px-3 py-2">
                    <div className="text-gray-400 dark:text-gray-500">Confidence</div>
                    <div className="font-semibold">{finding.confidenceScore}/100</div>
                  </div>
                  <div className="rounded-lg bg-gray-50 dark:bg-gray-900 px-3 py-2">
                    <div className="text-gray-400 dark:text-gray-500">Impact</div>
                    <div className="font-semibold">{finding.impactScore}/100</div>
                  </div>
                  <div className="rounded-lg bg-gray-50 dark:bg-gray-900 px-3 py-2">
                    <div className="text-gray-400 dark:text-gray-500">Policies</div>
                    <div className="font-semibold">{finding.policyCount}</div>
                  </div>
                  <div className="rounded-lg bg-gray-50 dark:bg-gray-900 px-3 py-2">
                    <div className="text-gray-400 dark:text-gray-500">Exact overlaps</div>
                    <div className="font-semibold">{finding.sharedSettingCount}</div>
                  </div>
                </div>
              </div>
            </button>

            {isExpanded && (
              <div className="border-t border-gray-200 dark:border-gray-700 px-5 py-5 space-y-5">
                <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-sm">
                  <div className="rounded-lg bg-gray-50 dark:bg-gray-900 px-3 py-3">
                    <div className="text-gray-400 dark:text-gray-500">Shared settings</div>
                    <div className="font-semibold">{finding.sharedSettingCount}</div>
                  </div>
                  <div className="rounded-lg bg-gray-50 dark:bg-gray-900 px-3 py-3">
                    <div className="text-gray-400 dark:text-gray-500">Matching settings</div>
                    <div className="font-semibold">{finding.matchingSettingCount}</div>
                  </div>
                  <div className="rounded-lg bg-gray-50 dark:bg-gray-900 px-3 py-3">
                    <div className="text-gray-400 dark:text-gray-500">Unique settings</div>
                    <div className="font-semibold">{finding.uniqueSettingCount}</div>
                  </div>
                  <div className="rounded-lg bg-gray-50 dark:bg-gray-900 px-3 py-3">
                    <div className="text-gray-400 dark:text-gray-500">Conflicts</div>
                    <div className="font-semibold">{finding.conflictCount}</div>
                  </div>
                </div>

                <div>
                  <h4 className="text-sm font-semibold mb-2">Why this surfaced</h4>
                  <p className="text-sm text-gray-500 dark:text-gray-400">{finding.rationale}</p>
                </div>

                <div>
                  <h4 className="text-sm font-semibold mb-2">Example settings</h4>
                  <div className="flex flex-wrap gap-2">
                    {finding.exampleSettings.map((setting) => (
                      <span
                        key={setting}
                        className="inline-flex items-center rounded-full bg-gray-100 dark:bg-gray-700/60 px-3 py-1 text-xs text-gray-600 dark:text-gray-300"
                      >
                        {setting}
                      </span>
                    ))}
                  </div>
                </div>

                <div>
                  <h4 className="text-sm font-semibold mb-2">Policies in cluster</h4>
                  <div className="space-y-2">
                    {finding.policies.map((policy) => (
                      <div key={policy.policyId} className="rounded-lg border border-gray-200 dark:border-gray-700 px-4 py-3">
                        <div className="flex flex-col gap-1 md:flex-row md:items-center md:justify-between">
                          <div>
                            <div className="font-medium">{policy.policyName}</div>
                            <div className="text-sm text-gray-500 dark:text-gray-400">{policyTypeLabel(policy.policyType)}</div>
                          </div>
                          <div className="text-sm text-gray-500 dark:text-gray-400">
                            {policy.platform ?? 'Unknown'} · {policy.settingCount} settings in domain
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
