import { useState, useCallback } from 'react'
import type { Policy, Group, GroupPolicyMapping } from '../types'
import { POLICY_TYPES } from '../types'
import { getGroupPolicies, getPolicyGroups } from '../services/api'
import type { PolicyGroupTarget } from '../services/api'

interface GroupExplorerProps {
  policies: Policy[]
  groups: Group[]
}

type Mode = 'groupToPolicies' | 'policyToGroups'

function Spinner({ className = 'h-5 w-5' }: { className?: string }) {
  return (
    <svg className={`animate-spin ${className}`} viewBox="0 0 24 24" fill="none">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
    </svg>
  )
}

function AssignmentBadge({ source }: { source: string }) {
  const styles: Record<string, string> = {
    Direct: 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300',
    Inherited: 'bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300',
    'All Users': 'bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300',
    'All Devices': 'bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300',
  }
  return (
    <span className={`inline-block text-xs font-medium px-2 py-0.5 rounded ${styles[source] ?? 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300'}`}>
      {source}
    </span>
  )
}

function AssignmentTypeBadge({ type }: { type: string }) {
  const isExclude = type.toLowerCase().includes('exclude')
  return (
    <span className={`inline-block text-xs font-medium px-2 py-0.5 rounded ${
      isExclude
        ? 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300'
        : 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300'
    }`}>
      {isExclude ? 'Exclude' : 'Include'}
    </span>
  )
}

function SettingsView({ settings }: { settings: unknown[] }) {
  if (!settings || settings.length === 0) {
    return <p className="text-sm text-gray-400 dark:text-gray-500 italic">No settings data</p>
  }
  return (
    <pre className="text-xs bg-gray-50 dark:bg-gray-900 rounded p-3 overflow-x-auto max-h-64 text-gray-700 dark:text-gray-300">
      {JSON.stringify(settings, null, 2)}
    </pre>
  )
}

// ─── Group → Policies Mode ─────────────────────────────────────────

function GroupToPolicies({ groups }: { groups: Group[] }) {
  const [query, setQuery] = useState('')
  const [selectedGroup, setSelectedGroup] = useState<Group | null>(null)
  const [mappings, setMappings] = useState<GroupPolicyMapping[]>([])
  const [loadingPolicies, setLoadingPolicies] = useState(false)
  const [expandedPolicies, setExpandedPolicies] = useState<Set<string>>(new Set())
  const [collapsedTypes, setCollapsedTypes] = useState<Set<string>>(new Set())

  // Client-side filter
  const filtered = query.trim()
    ? groups.filter((g) =>
        g.displayName.toLowerCase().includes(query.toLowerCase())
      )
    : groups

  const handleSelectGroup = useCallback(async (group: Group) => {
    setSelectedGroup(group)
    setLoadingPolicies(true)
    setExpandedPolicies(new Set())
    try {
      const data = await getGroupPolicies(group.id)
      setMappings(data)
    } catch {
      setMappings([])
    } finally {
      setLoadingPolicies(false)
    }
  }, [])

  const togglePolicy = (id: string) => {
    setExpandedPolicies((prev) => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  const toggleType = (key: string) => {
    setCollapsedTypes((prev) => {
      const next = new Set(prev)
      next.has(key) ? next.delete(key) : next.add(key)
      return next
    })
  }

  // Flatten all mappings into policies with their assignment source
  const allPoliciesWithSource = mappings.flatMap((m) =>
    m.policies.map((p) => ({ ...p, _source: m.assignmentSource }))
  )

  const sourceLabel: Record<string, string> = {
    direct: 'Direct',
    inherited: 'Inherited',
    all_users: 'All Users',
    all_devices: 'All Devices',
  }

  const policiesByType = POLICY_TYPES.map((pt) => ({
    ...pt,
    policies: allPoliciesWithSource.filter((p) => p.policyType === pt.key),
  })).filter((t) => t.policies.length > 0)

  return (
    <div className="flex gap-6 h-[calc(100vh-16rem)]">
      {/* Left panel — group search & list */}
      <div className="w-80 flex-shrink-0 flex flex-col">
        <div className="relative">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter groups…"
            className="w-full px-4 py-2.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-blue-400 placeholder-gray-400"
          />
        </div>

        <p className="text-xs text-gray-400 dark:text-gray-500 mt-2 px-1">
          {groups.length} groups{query.trim() ? ` · ${filtered.length} shown` : ''}
        </p>

        <div className="mt-2 flex-1 overflow-y-auto space-y-1">
          {filtered.length === 0 && (
            <p className="text-sm text-gray-400 dark:text-gray-500 text-center py-8">
              {query.trim() ? 'No groups match your filter' : 'No groups found'}
            </p>
          )}
          {filtered.map((group) => (
            <button
              key={group.id}
              onClick={() => handleSelectGroup(group)}
              className={`w-full text-left px-4 py-3 rounded-lg transition-colors ${
                selectedGroup?.id === group.id
                  ? 'bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-700'
                  : 'hover:bg-gray-50 dark:hover:bg-gray-800 border border-transparent'
              }`}
            >
              <p className="text-sm font-medium truncate">{group.displayName}</p>
              {group.memberCount != null && (
                <p className="text-xs text-gray-400 dark:text-gray-500 mt-0.5">
                  {group.memberCount} members
                </p>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* Right panel — policies for selected group */}
      <div className="flex-1 overflow-y-auto">
        {!selectedGroup && (
          <div className="flex items-center justify-center h-full text-gray-400 dark:text-gray-500">
            <p className="text-sm">Select a group to view its policies</p>
          </div>
        )}

        {selectedGroup && loadingPolicies && (
          <div className="flex items-center justify-center h-full">
            <Spinner className="h-8 w-8 text-blue-500" />
          </div>
        )}

        {selectedGroup && !loadingPolicies && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold">
                {selectedGroup.displayName}
              </h2>
              <span className="text-sm text-gray-400 dark:text-gray-500">
                {allPoliciesWithSource.length} policies
              </span>
            </div>

            {policiesByType.length === 0 && (
              <p className="text-sm text-gray-400 dark:text-gray-500 py-8 text-center">
                No policies assigned to this group
              </p>
            )}

            {policiesByType.map((section) => (
              <div key={section.key} className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
                <button
                  onClick={() => toggleType(section.key)}
                  className="w-full flex items-center justify-between px-5 py-3 hover:bg-gray-50 dark:hover:bg-gray-700/30 transition-colors"
                >
                  <span className="font-medium text-sm">
                    {section.icon} {section.label}
                    <span className="ml-2 text-gray-400 font-normal">({section.policies.length})</span>
                  </span>
                  <span className="text-gray-400 text-xs">{collapsedTypes.has(section.key) ? '▸' : '▾'}</span>
                </button>

                {!collapsedTypes.has(section.key) && (
                  <div className="border-t border-gray-100 dark:border-gray-700 divide-y divide-gray-50 dark:divide-gray-700/50">
                    {section.policies.map((policy) => (
                      <div key={policy.id}>
                        <button
                          onClick={() => togglePolicy(policy.id)}
                          className="w-full text-left px-5 py-3 hover:bg-gray-50 dark:hover:bg-gray-700/20 transition-colors"
                        >
                          <div className="flex items-center gap-2">
                            <span className="text-xs text-gray-400">{expandedPolicies.has(policy.id) ? '▾' : '▸'}</span>
                            <span className="text-sm font-medium flex-1 truncate">{policy.displayName}</span>
                            <AssignmentBadge source={sourceLabel[policy._source] ?? policy._source} />
                          </div>
                          {policy.description && (
                            <p className="text-xs text-gray-400 dark:text-gray-500 mt-1 ml-5 truncate">
                              {policy.description}
                            </p>
                          )}
                        </button>

                        {expandedPolicies.has(policy.id) && (
                          <div className="px-5 pb-4 ml-5">
                            <SettingsView settings={policy.settings} />
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Policy → Groups Mode ───────────────────────────────────────────

function PolicyToGroups({ policies }: { policies: Policy[] }) {
  const [filter, setFilter] = useState('')
  const [selectedPolicy, setSelectedPolicy] = useState<Policy | null>(null)
  const [targetGroups, setTargetGroups] = useState<PolicyGroupTarget[]>([])
  const [loading, setLoading] = useState(false)

  const filtered = policies.filter((p) =>
    p.displayName.toLowerCase().includes(filter.toLowerCase()),
  )

  const handleSelectPolicy = useCallback(async (policy: Policy) => {
    setSelectedPolicy(policy)
    setLoading(true)
    try {
      const data = await getPolicyGroups(policy.id)
      setTargetGroups(data)
    } catch {
      setTargetGroups([])
    } finally {
      setLoading(false)
    }
  }, [])

  const assignmentLabel = (type: string) => {
    if (type === 'all_users') return 'All Users'
    if (type === 'all_devices') return 'All Devices'
    return type.charAt(0).toUpperCase() + type.slice(1)
  }

  return (
    <div className="flex gap-6 h-[calc(100vh-16rem)]">
      {/* Left panel — policy list */}
      <div className="w-80 flex-shrink-0 flex flex-col">
        <input
          type="text"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter policies…"
          className="w-full px-4 py-2.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-blue-400 placeholder-gray-400"
        />

        <div className="mt-3 flex-1 overflow-y-auto space-y-1">
          {filtered.length === 0 && (
            <p className="text-sm text-gray-400 dark:text-gray-500 text-center py-8">
              {policies.length === 0 ? 'Load policies from the Dashboard first' : 'No policies match'}
            </p>
          )}
          {filtered.map((policy) => {
            const typeInfo = POLICY_TYPES.find((t) => t.key === policy.policyType)
            return (
              <button
                key={policy.id}
                onClick={() => handleSelectPolicy(policy)}
                className={`w-full text-left px-4 py-3 rounded-lg transition-colors ${
                  selectedPolicy?.id === policy.id
                    ? 'bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-700'
                    : 'hover:bg-gray-50 dark:hover:bg-gray-800 border border-transparent'
                }`}
              >
                <p className="text-sm font-medium truncate">{policy.displayName}</p>
                <p className="text-xs text-gray-400 dark:text-gray-500 mt-0.5">
                  {typeInfo ? `${typeInfo.icon} ${typeInfo.label}` : policy.policyType}
                </p>
              </button>
            )
          })}
        </div>
      </div>

      {/* Right panel — groups for selected policy */}
      <div className="flex-1 overflow-y-auto">
        {!selectedPolicy && (
          <div className="flex items-center justify-center h-full text-gray-400 dark:text-gray-500">
            <p className="text-sm">Select a policy to view its target groups</p>
          </div>
        )}

        {selectedPolicy && loading && (
          <div className="flex items-center justify-center h-full">
            <Spinner className="h-8 w-8 text-blue-500" />
          </div>
        )}

        {selectedPolicy && !loading && (
          <div className="space-y-4">
            <h2 className="text-lg font-semibold">{selectedPolicy.displayName}</h2>
            {selectedPolicy.description && (
              <p className="text-sm text-gray-500 dark:text-gray-400">{selectedPolicy.description}</p>
            )}

            {targetGroups.length === 0 ? (
              <p className="text-sm text-gray-400 dark:text-gray-500 py-8 text-center">
                No groups targeted by this policy
              </p>
            ) : (
              <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-gray-100 dark:border-gray-700 text-left text-sm text-gray-500 dark:text-gray-400">
                      <th className="px-5 py-3 font-medium">Group</th>
                      <th className="px-5 py-3 font-medium">Assignment</th>
                      <th className="px-5 py-3 font-medium">Filter</th>
                    </tr>
                  </thead>
                  <tbody>
                    {targetGroups.map((g, idx) => (
                      <tr key={g.group_id ?? `special-${idx}`} className="border-b border-gray-50 dark:border-gray-700/50 hover:bg-gray-50 dark:hover:bg-gray-700/30 transition-colors">
                        <td className="px-5 py-3">
                          <p className="text-sm font-medium">
                            {g.group_name ?? (g.group_id ? g.group_id : assignmentLabel(g.assignment_type))}
                          </p>
                        </td>
                        <td className="px-5 py-3">
                          <AssignmentTypeBadge type={g.assignment_type} />
                        </td>
                        <td className="px-5 py-3 text-sm text-gray-500 dark:text-gray-400">
                          {g.filter_type ?? '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Main Component ──────────────────────────────────────────────────

export default function GroupExplorer({ policies, groups }: GroupExplorerProps) {
  const [mode, setMode] = useState<Mode>('groupToPolicies')

  return (
    <div className="space-y-4">
      {/* Mode toggle */}
      <div className="flex items-center gap-2">
        <div className="inline-flex rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 p-1">
          <button
            onClick={() => setMode('groupToPolicies')}
            className={`px-4 py-1.5 text-sm font-medium rounded-md transition-colors ${
              mode === 'groupToPolicies'
                ? 'bg-blue-600 text-white'
                : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200'
            }`}
          >
            Group → Policies
          </button>
          <button
            onClick={() => setMode('policyToGroups')}
            className={`px-4 py-1.5 text-sm font-medium rounded-md transition-colors ${
              mode === 'policyToGroups'
                ? 'bg-blue-600 text-white'
                : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200'
            }`}
          >
            Policy → Groups
          </button>
        </div>
      </div>

      {/* Active view */}
      {mode === 'groupToPolicies' ? <GroupToPolicies groups={groups} /> : <PolicyToGroups policies={policies} />}
    </div>
  )
}
