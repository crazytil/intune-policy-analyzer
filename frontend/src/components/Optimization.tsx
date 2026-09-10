import { useEffect, useState } from 'react'
import type { Group, OptimizationAnalysisResult, OptimizationPlatform, OptimizationPolicyPreview, Policy } from '../types'
import { POLICY_TYPES } from '../types'
import { analyzeOptimization, getPolicy } from '../services/api'

const PLATFORMS: { value: OptimizationPlatform; label: string }[] = [
  { value: 'windows', label: 'Windows' },
  { value: 'macos', label: 'macOS' },
  { value: 'ios', label: 'iOS/iPadOS' },
  { value: 'android', label: 'Android' },
  { value: 'linux', label: 'Linux' },
]

const buttonClass = 'rounded-md border border-slate-300 px-3 py-2 text-sm font-semibold hover:bg-slate-100 disabled:opacity-50 dark:border-white/15 dark:hover:bg-white/10'
const selectClass = 'mt-2 block w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-white/15 dark:bg-[#121b19]'

function PolicyDetails({ preview }: { preview: OptimizationPolicyPreview }) {
  const [showComplete, setShowComplete] = useState(false)
  const [policy, setPolicy] = useState<Policy | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    if (!showComplete) return
    let cancelled = false
    setPolicy(null)
    setError(null)
    getPolicy(preview.policyId).then(
      (next) => { if (!cancelled) setPolicy(next) },
      (err) => { if (!cancelled) setError(err instanceof Error ? err.message : 'Unable to load policy settings') },
    )
    return () => { cancelled = true }
  }, [showComplete, preview.policyId, attempt])

  return (
    <details className="border-t border-slate-200 py-4 dark:border-white/10">
      <summary className="cursor-pointer break-words text-sm font-semibold text-[#125f58] dark:text-[#6ee7d8]">
        {preview.policyName}
        <span className="ml-2 font-normal text-slate-500 dark:text-slate-400">
          {POLICY_TYPES.find((type) => type.key === preview.policyType)?.label ?? preview.policyType} · {preview.platform ?? 'Unknown platform'} · {preview.settingCount} settings
        </span>
      </summary>
      <div className="mt-4 space-y-4 pl-4">
        <div>
          <h4 className="text-sm font-semibold">Affected settings</h4>
          {preview.affectedSettings.length ? (
            <ul className="mt-2 list-inside list-disc space-y-1 break-words text-sm text-slate-600 dark:text-slate-300">
              {preview.affectedSettings.map((setting, index) => <li key={index}>{setting}</li>)}
            </ul>
          ) : <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">No affected settings listed.</p>}
        </div>
        <button className={buttonClass} aria-expanded={showComplete} onClick={() => setShowComplete(!showComplete)}>
          {showComplete ? 'Hide complete settings' : 'Load complete settings'}
        </button>
        {showComplete && (
          <div>
            <h4 className="mb-2 text-sm font-semibold">Complete settings</h4>
            {error ? (
              <div role="alert" className="space-y-2 text-sm text-red-700 dark:text-red-300">
                <p>{error}</p><button className={buttonClass} onClick={() => setAttempt(attempt + 1)}>Retry settings</button>
              </div>
            ) : !policy ? <p role="status" className="text-sm">Loading policy settings…</p> : (
              <div>
                {!policy.settings.length && <p className="mb-2 text-xs text-slate-500 dark:text-slate-400">This policy type stores settings in its policy payload, shown below.</p>}
                <pre className="max-h-96 overflow-auto rounded-md bg-slate-100 p-4 text-xs dark:bg-black/20">{JSON.stringify(policy.settings.length ? policy.settings : policy.raw, null, 2)}</pre>
              </div>
            )}
          </div>
        )}
      </div>
    </details>
  )
}

export default function Optimization({ isReady, loading: inventoryLoading, policies, groups }: {
  isReady: boolean
  loading: boolean
  policies: Policy[]
  groups: Group[]
}) {
  const [platforms, setPlatforms] = useState<OptimizationPlatform[]>([])
  const [groupId, setGroupId] = useState('')
  const [domain, setDomain] = useState('')
  const [result, setResult] = useState<OptimizationAnalysisResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    let cancelled = false
    setResult(null)
    setError(null)
    if (!isReady || inventoryLoading) return
    setLoading(true)
    analyzeOptimization({ platforms, groupId: groupId || undefined }).then(
      (next) => { if (!cancelled) setResult(next) },
      (err) => { if (!cancelled) setError(err instanceof Error ? err.message : 'Unable to analyse policies') },
    ).finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [isReady, inventoryLoading, policies, platforms, groupId, attempt])

  const busy = inventoryLoading || loading
  const findings = result?.findings.filter((finding) => !domain || finding.domain === domain) ?? []

  return (
    <div className="space-y-8">
      <header className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[#147d72] dark:text-[#6ee7d8]">Read-only review</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-[-0.04em] sm:text-4xl">Policy optimisation</h1>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-600 dark:text-slate-300">Review consolidation candidates and fragmented settings. Findings are starting points for investigation, not instructions to merge policies. No tenant changes are made.</p>
        </div>
        <button className={`${buttonClass} shrink-0 self-start`} disabled={!isReady || busy} onClick={() => setAttempt(attempt + 1)}>Run analysis again</button>
      </header>

      <section aria-label="Optimisation filters" className="space-y-5 border border-slate-200 bg-white p-5 dark:border-white/10 dark:bg-[#121b19]">
        <fieldset>
          <legend className="text-xs font-semibold uppercase tracking-wider text-slate-600 dark:text-slate-300">Platforms</legend>
          <div className="mt-3 flex flex-wrap gap-3">
            {PLATFORMS.map(({ value, label }) => (
              <label key={value} className="flex cursor-pointer items-center gap-2 rounded-md border border-slate-200 px-3 py-2 text-sm dark:border-white/15">
                <input type="checkbox" className="accent-[#147d72]" checked={platforms.includes(value)} onChange={() => {
                  setPlatforms((current) => current.includes(value) ? current.filter((item) => item !== value) : [...current, value])
                  setDomain('')
                }} />{label}
              </label>
            ))}
          </div>
          <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">No selection includes all platforms.</p>
        </fieldset>
        <div className="grid gap-4 sm:grid-cols-2">
          <label className="text-sm font-semibold">Group (direct includes)
            <select aria-describedby="optimization-group-help" className={selectClass} value={groupId} onChange={(event) => { setGroupId(event.target.value); setDomain('') }}>
              <option value="">No group filter</option>
              {groups.map((group) => <option key={group.id} value={group.id}>{group.displayName}</option>)}
            </select>
          </label>
          <label className="text-sm font-semibold">Domain
            <select className={selectClass} value={domain} onChange={(event) => setDomain(event.target.value)}>
              <option value="">All domains</option>
              {Array.from(new Set([...(result?.summary.domains ?? []), ...(domain ? [domain] : [])])).map((item) => <option key={item} value={item}>{item}</option>)}
            </select>
          </label>
        </div>
        <p id="optimization-group-help" className="text-xs leading-5 text-slate-500 dark:text-slate-400">Group filtering matches direct include assignments only. It does not expand nested membership, All Users or All Devices.</p>
        <details className="text-xs leading-5 text-slate-500 dark:text-slate-400">
          <summary className="cursor-pointer font-semibold">Analysis coverage and limits</summary>
          <p className="mt-2">Covers Device Configuration, Compliance, Compliance v2, Settings Catalog and Endpoint Security. Unknown platforms and unresolved payloads are omitted. Comparisons require identical assignments, including exclusions and filters, and keep policy families, schemas, templates and technologies separate.</p>
        </details>
      </section>

      {!isReady || inventoryLoading ? (
        <p role="status" className="py-8 text-center text-slate-600 dark:text-slate-300">{inventoryLoading ? 'Loading policy inventory…' : 'Policy inventory is not ready. Load or retry it from Overview.'}</p>
      ) : loading ? (
        <p role="status" className="py-8 text-center text-slate-600 dark:text-slate-300">Analysing policy optimisation candidates…</p>
      ) : error ? (
        <div role="alert" className="space-y-3 border-l-4 border-red-500 bg-red-50 p-5 text-sm text-red-800 dark:bg-red-950/30 dark:text-red-200">
          <p>{error}</p><button className={buttonClass} onClick={() => setAttempt(attempt + 1)}>Retry analysis</button>
        </div>
      ) : result && (
        <>
          <div className="grid gap-4 sm:grid-cols-3">
            {[
              ['Review findings', result.summary.totalFindings],
              ['Consolidation candidates', result.summary.consolidationCandidates],
              ['Fragmentation hotspots', result.summary.fragmentationHotspots],
            ].map(([label, count]) => (
              <div key={label} className="border-t-2 border-[#147d72] bg-white p-5 dark:bg-[#121b19]">
                <p className="text-xs font-semibold uppercase tracking-wider text-slate-600 dark:text-slate-300">{label}</p>
                <p className="mt-4 text-4xl font-semibold tabular-nums tracking-tight">{count}</p>
              </div>
            ))}
          </div>
          <p className="text-sm text-slate-500 dark:text-slate-400">{findings.length} findings shown. Totals reflect the selected platforms and group, before the domain filter.</p>
          {findings.length === 0 ? (
            <div role="status" className="border border-dashed border-slate-300 p-8 text-center dark:border-white/15">
              <h2 className="font-semibold">No review candidates in this scope</h2>
              <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">Try another filter. This does not establish that policies are conflict-free or optimal.</p>
            </div>
          ) : <div className="space-y-4">
            {findings.map((finding) => (
              <details key={finding.findingId} className="border border-slate-200 bg-white p-5 dark:border-white/10 dark:bg-[#121b19]">
                <summary className="cursor-pointer break-words font-semibold">
                  {finding.title}
                  <span className="ml-3 inline-block text-xs font-medium text-[#147d72] dark:text-[#6ee7d8]">{finding.recommendationType === 'consolidationCandidate' ? 'Consolidation candidate' : 'Fragmentation hotspot'}</span>
                  <span className="mt-2 block text-sm font-normal text-slate-600 dark:text-slate-300">{finding.summary}</span>
                  <span className="mt-2 block text-xs font-normal text-slate-500 dark:text-slate-400">{finding.domain} · {finding.audience} · {finding.platforms.join(', ') || 'All platforms'} · {finding.policyCount} policies</span>
                </summary>
                <div className="mt-5 space-y-5">
                  <p className="text-sm leading-6 text-slate-600 dark:text-slate-300">{finding.rationale}</p>
                  <dl className="flex flex-wrap gap-x-8 gap-y-3 text-sm">
                    {[
                      ['Shared settings', finding.sharedSettingCount], ['Unique settings', finding.uniqueSettingCount],
                      ['Matching settings', finding.matchingSettingCount], ['Conflicts across complete policies', finding.conflictCount],
                    ].map(([label, value]) => <div key={label}><dt className="text-slate-500 dark:text-slate-400">{label}</dt><dd className="mt-1 font-semibold tabular-nums">{value}</dd></div>)}
                  </dl>
                  {finding.exampleSettings.length > 0 && <p className="break-words text-sm text-slate-600 dark:text-slate-300">Example settings: {finding.exampleSettings.join(', ')}</p>}
                  <div><h3 className="mb-3 text-sm font-semibold">Policies to review</h3>{finding.policies.map((preview) => <PolicyDetails key={preview.policyId} preview={preview} />)}</div>
                </div>
              </details>
            ))}
          </div>}
        </>
      )}
    </div>
  )
}
