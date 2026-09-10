import { useState, useEffect, useCallback, useRef } from 'react'
import type { AuthStatus, Policy, Group } from './types'
import { getAuthStatus, login, logout, fetchPolicies, fetchAllGroups } from './services/api'
import Dashboard from './components/Dashboard'
import GroupExplorer from './components/GroupExplorer'
import ConflictAnalyzer from './components/ConflictAnalyzer'
import Optimization from './components/Optimization'

type Tab = 'dashboard' | 'groupExplorer' | 'conflicts' | 'optimization'

const POLICY_CACHE_KEY = 'intune-policies-cache'
const GROUP_CACHE_KEY = 'intune-groups-cache'
const CACHE_VERSION = 2

interface DataCache<T> {
  version: number
  tenantId: string
  userName: string
  data: T
  timestamp: number
}

const CACHE_MAX_AGE_MS = 30 * 60 * 1000 // 30 minutes

function getStorageCandidates(): Storage[] {
  if (typeof window === 'undefined') return []
  return [window.localStorage, window.sessionStorage]
}

function loadCache<T>(key: string, tenantId: string, userName: string): DataCache<T> | null {
  for (const storage of getStorageCandidates()) {
    try {
      const raw = storage.getItem(key)
      if (!raw) continue
      const cache: DataCache<T> = JSON.parse(raw)
      if (cache.version !== CACHE_VERSION) {
        storage.removeItem(key)
        continue
      }

      if (cache.tenantId === tenantId && cache.userName === userName) {
        if (Date.now() - cache.timestamp > CACHE_MAX_AGE_MS) {
          storage.removeItem(key)
          return null
        }
        return cache
      }
    } catch {
      /* ignore */
    }
  }
  return null
}

function stripRawForCache(policies: Policy[]): Policy[] {
  return policies.map(({ raw, ...rest }) => ({ ...rest, raw: {} }))
}

function saveCache<T>(key: string, tenantId: string, userName: string, data: T) {
  const cache: DataCache<T> = {
    version: CACHE_VERSION,
    tenantId,
    userName,
    data,
    timestamp: Date.now(),
  }
  const serialized = JSON.stringify(cache)

  for (const storage of getStorageCandidates()) {
    try {
      storage.setItem(key, serialized)
      return
    } catch {
      try { storage.removeItem(key) } catch { /* ignore */ }
    }
  }
}

function clearAllCaches() {
  for (const storage of getStorageCandidates()) {
    try {
      storage.removeItem(POLICY_CACHE_KEY)
      storage.removeItem(GROUP_CACHE_KEY)
    } catch { /* ignore */ }
  }
}

function Spinner({ className = 'h-4 w-4' }: { className?: string }) {
  return (
    <svg className={`animate-spin ${className}`} viewBox="0 0 24 24" fill="none">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
    </svg>
  )
}

function ProductMark({ className = 'h-9 w-9' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 36 36" fill="none" aria-hidden="true">
      <rect width="36" height="36" rx="10" fill="currentColor" />
      <path d="M10 11.5h16M10 18h10M10 24.5h7" stroke="white" strokeWidth="2.5" strokeLinecap="round" />
      <circle cx="25" cy="23.5" r="4.5" fill="#D9F99D" />
      <path d="m23.2 23.5 1.2 1.2 2.4-2.6" stroke="#16332F" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

export default function App() {
  const [darkMode, setDarkMode] = useState(() => {
    if (typeof window !== 'undefined') {
      return window.matchMedia('(prefers-color-scheme: dark)').matches
    }
    return false
  })
  const [auth, setAuth] = useState<AuthStatus | null>(null)
  const [authLoading, setAuthLoading] = useState(true)
  const [authActionLoading, setAuthActionLoading] = useState(false)
  const [activeTab, setActiveTab] = useState<Tab>('dashboard')

  // Data state
  const [policies, setPolicies] = useState<Policy[]>([])
  const [groups, setGroups] = useState<Group[]>([])
  const [dataLoading, setDataLoading] = useState(false)
  const [dataLoadedAt, setDataLoadedAt] = useState<number | null>(null)
  const [fromCache, setFromCache] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [loadedForKey, setLoadedForKey] = useState<string | null>(null)
  const backgroundRefreshRef = useRef<Promise<void> | null>(null)

  const authCacheKey = auth?.tenantId && auth?.userName
    ? `${auth.tenantId}:${auth.userName}`
    : null

  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add('dark')
    } else {
      document.documentElement.classList.remove('dark')
    }
  }, [darkMode])

  useEffect(() => {
    getAuthStatus()
      .then((status) => {
        setAuth(status)
        return status
      })
      .catch(() => {
        setAuth({ isAuthenticated: false, userName: null, tenantId: null })
        return null
      })
      .finally(() => setAuthLoading(false))
  }, [])

  const commitLoadedData = useCallback((policiesData: Policy[], groupsData: Group[], loadedAt: number, cached: boolean) => {
    setPolicies(policiesData)
    setGroups(groupsData)
    setDataLoadedAt(loadedAt)
    setFromCache(cached)
    setLoadedForKey(authCacheKey)
  }, [authCacheKey])

  const refreshAllData = useCallback(async (options?: { forceRefresh?: boolean; silent?: boolean }) => {
    if (!auth?.tenantId || !auth?.userName) return

    const forceRefresh = options?.forceRefresh ?? false
    const silent = options?.silent ?? false

    if (!silent) {
      setDataLoading(true)
      setError(null)
    }

    try {
      const [policiesData, groupsData] = await Promise.all([
        fetchPolicies({ refresh: forceRefresh }),
        fetchAllGroups(),
      ])
      const now = Date.now()
      commitLoadedData(policiesData, groupsData, now, false)
      saveCache(POLICY_CACHE_KEY, auth.tenantId, auth.userName, stripRawForCache(policiesData))
      saveCache(GROUP_CACHE_KEY, auth.tenantId, auth.userName, groupsData)
    } catch (e) {
      if (!silent) {
        setError(e instanceof Error ? e.message : 'Failed to load data')
      }
    } finally {
      if (!silent) {
        setDataLoading(false)
      }
    }
  }, [auth?.tenantId, auth?.userName, commitLoadedData])

  const queueBackgroundRefresh = useCallback(() => {
    if (backgroundRefreshRef.current) return backgroundRefreshRef.current

    const refreshPromise = refreshAllData({ silent: true })
      .catch(() => undefined)
      .finally(() => {
        backgroundRefreshRef.current = null
      })

    backgroundRefreshRef.current = refreshPromise
    return refreshPromise
  }, [refreshAllData])

  // Load all data (policies + groups) — from cache or fresh
  const loadAllData = useCallback(async (forceRefresh = false) => {
    if (!auth?.tenantId || !auth?.userName) return

    if (!forceRefresh) {
      const cachedPolicies = loadCache<Policy[]>(POLICY_CACHE_KEY, auth.tenantId, auth.userName)
      const cachedGroups = loadCache<Group[]>(GROUP_CACHE_KEY, auth.tenantId, auth.userName)
      if (cachedPolicies && cachedPolicies.data.length > 0 && cachedGroups && cachedGroups.data.length > 0) {
        commitLoadedData(
          cachedPolicies.data,
          cachedGroups.data,
          Math.min(cachedPolicies.timestamp, cachedGroups.timestamp),
          true,
        )
        void queueBackgroundRefresh()
        return
      }
    }

    await refreshAllData({ forceRefresh })
  }, [auth?.tenantId, auth?.userName, commitLoadedData, queueBackgroundRefresh, refreshAllData])

  // Auto-load when authenticated
  useEffect(() => {
    if (auth?.isAuthenticated && !dataLoading && (policies.length === 0 || loadedForKey !== authCacheKey)) {
      loadAllData(false)
    }
  }, [auth?.isAuthenticated, authCacheKey, loadedForKey, policies.length]) // eslint-disable-line react-hooks/exhaustive-deps

  const handleRefresh = useCallback(() => {
    loadAllData(true)
  }, [loadAllData])

  const handleLogin = async () => {
    setError(null)
    setAuthActionLoading(true)
    try {
      const status = await login()
      setAuth(status)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Login failed')
    } finally {
      setAuthActionLoading(false)
    }
  }

  const handleLogout = async () => {
    setAuthActionLoading(true)
    try {
      await logout()
      setAuth({ isAuthenticated: false, userName: null, tenantId: null })
      setPolicies([])
      setGroups([])
      setDataLoadedAt(null)
      setLoadedForKey(null)
      setFromCache(false)
      clearAllCaches()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Logout failed')
    } finally {
      setAuthActionLoading(false)
    }
  }

  const tabs: { key: Tab; label: string; shortLabel: string; marker: string; disabled: boolean }[] = [
    { key: 'dashboard', label: 'Overview', shortLabel: 'Overview', marker: '01', disabled: false },
    { key: 'groupExplorer', label: 'Assignment explorer', shortLabel: 'Explorer', marker: '02', disabled: false },
    { key: 'conflicts', label: 'Conflict analysis', shortLabel: 'Conflicts', marker: '03', disabled: false },
    { key: 'optimization', label: 'Optimisation', shortLabel: 'Optimise', marker: '04', disabled: false },
  ]

  return (
    <div className="min-h-screen bg-[#f3f5f2] text-slate-900 transition-colors dark:bg-[#0c1211] dark:text-slate-100">
      <a href="#main-content" className="sr-only z-50 rounded-md bg-white px-4 py-2 text-sm font-semibold focus:not-sr-only focus:fixed focus:left-4 focus:top-4">Skip to content</a>
      <header className="border-b border-slate-200/80 bg-[#f8faf7]/90 backdrop-blur-xl dark:border-white/10 dark:bg-[#101716]/90">
        <div className="mx-auto flex min-h-[72px] max-w-[1440px] items-center justify-between gap-4 px-4 sm:px-6 lg:px-10">
          <div className="flex min-w-0 items-center gap-3">
            <ProductMark className="h-9 w-9 shrink-0 text-[#147d72]" />
            <div className="min-w-0">
              <p className="truncate text-sm font-semibold tracking-tight sm:text-base">Intune Policy Analyser</p>
              <p className="hidden text-[11px] font-medium uppercase tracking-[0.16em] text-slate-500 sm:block dark:text-slate-400">Configuration intelligence</p>
            </div>
          </div>

          <div className="flex items-center gap-2 sm:gap-3">
            {authLoading ? (
              <span className="hidden text-sm text-slate-500 sm:inline">Checking session…</span>
            ) : auth?.isAuthenticated ? (
              <>
                <div className="hidden text-right md:block">
                  <p className="max-w-56 truncate text-sm font-medium">{auth.userName}</p>
                  <p className="text-xs text-slate-500 dark:text-slate-400">Connected to Microsoft Intune</p>
                </div>
                <span className="hidden h-8 w-px bg-slate-200 dark:bg-white/10 md:block" />
                <button
                  onClick={handleLogout}
                  disabled={authActionLoading}
                  className="whitespace-nowrap rounded-md px-2 py-2 text-sm font-semibold text-slate-600 transition hover:bg-slate-200/70 hover:text-slate-900 active:translate-y-px disabled:opacity-50 sm:px-3 dark:text-slate-300 dark:hover:bg-white/10 dark:hover:text-white"
                >
                  <span className="sm:hidden">Exit</span><span className="hidden sm:inline">Sign out</span>
                </button>
              </>
            ) : (
              <button
                onClick={handleLogin}
                disabled={authActionLoading}
                className="hidden items-center gap-2 rounded-md bg-[#16332f] px-4 py-2.5 text-sm font-semibold text-white shadow-[0_8px_24px_rgba(22,51,47,0.15)] transition hover:-translate-y-0.5 hover:bg-[#214942] active:translate-y-0 disabled:opacity-60 sm:inline-flex"
              >
                {authActionLoading && <Spinner />}
                {authActionLoading ? 'Connecting…' : 'Sign in'}
              </button>
            )}
            <button
              onClick={() => setDarkMode(!darkMode)}
              className="grid h-10 w-10 place-items-center rounded-md border border-slate-200 bg-white text-slate-600 transition hover:border-slate-300 hover:text-slate-950 active:scale-[0.98] dark:border-white/10 dark:bg-white/5 dark:text-slate-300 dark:hover:bg-white/10"
              aria-label={darkMode ? 'Use light theme' : 'Use dark theme'}
              title={darkMode ? 'Use light theme' : 'Use dark theme'}
            >
              <span aria-hidden="true" className="text-base">{darkMode ? '☼' : '◐'}</span>
            </button>
          </div>
        </div>
      </header>

      {/* Error banner */}
      {error && (
        <div className="mx-auto mt-4 max-w-[1440px] px-4 sm:px-6 lg:px-10">
          <div role="alert" className="flex items-start justify-between gap-4 border-l-4 border-red-500 bg-red-50 px-4 py-3 text-red-800 dark:bg-red-950/40 dark:text-red-200">
            <span className="text-sm">{error}</span>
            <button
              onClick={() => setError(null)}
              className="rounded px-1 text-red-500 hover:bg-red-100 hover:text-red-700 dark:hover:bg-red-900/40 dark:hover:text-red-300"
              aria-label="Dismiss error"
            >
              ✕
            </button>
          </div>
        </div>
      )}

      {/* Not authenticated — landing page */}
      {!authLoading && !auth?.isAuthenticated && (
        <main id="main-content" className="relative isolate overflow-hidden">
          <div className="pointer-events-none absolute inset-0 -z-10 bg-[radial-gradient(circle_at_15%_10%,rgba(20,125,114,0.10),transparent_28%),radial-gradient(circle_at_82%_35%,rgba(132,204,22,0.08),transparent_24%)]" />
          <div className="mx-auto grid min-h-[calc(100dvh-73px)] max-w-[1440px] items-center gap-14 px-4 py-16 sm:px-6 lg:grid-cols-[0.92fr_1.08fr] lg:px-10 lg:py-20">
            <section className="max-w-2xl">
              <div className="mb-8 inline-flex items-center gap-2 border-l-2 border-[#147d72] pl-3 text-xs font-semibold uppercase tracking-[0.18em] text-[#147d72] dark:text-[#6ee7d8]">
                Read-only tenant analysis
              </div>
              <h1 className="max-w-xl text-balance text-5xl font-semibold leading-[0.98] tracking-[-0.055em] sm:text-6xl lg:text-7xl">
                See every policy. Find what conflicts.
              </h1>
              <p className="mt-7 max-w-xl text-pretty text-lg leading-8 text-slate-600 dark:text-slate-300">
                Trace Intune assignments from groups to settings, surface policy overlap, and review your tenant without making changes.
              </p>
              <div className="mt-9 flex flex-col items-start gap-4 sm:flex-row sm:items-center">
                <button
                  onClick={handleLogin}
                  disabled={authActionLoading}
                  className="inline-flex min-w-48 items-center justify-center gap-2 rounded-md bg-[#16332f] px-6 py-3.5 text-base font-semibold text-white shadow-[0_14px_35px_rgba(22,51,47,0.18)] transition hover:-translate-y-0.5 hover:bg-[#214942] active:translate-y-0 disabled:opacity-60 dark:bg-[#d9f99d] dark:text-[#16332f] dark:hover:bg-[#e5ffb4]"
                >
                  {authActionLoading && <Spinner />}
                  {authActionLoading ? 'Opening sign-in…' : 'Connect Microsoft Intune'}
                </button>
                <span className="text-sm text-slate-600 dark:text-slate-300">Uses your existing Graph PowerShell access</span>
              </div>
              <dl className="mt-12 grid max-w-xl grid-cols-3 border-t border-slate-300/80 pt-6 dark:border-white/15">
                <div><dt className="text-2xl font-semibold tabular-nums">12</dt><dd className="mt-1 text-xs text-slate-500 dark:text-slate-400">Policy families</dd></div>
                <div><dt className="text-2xl font-semibold">Zero</dt><dd className="mt-1 text-xs text-slate-500 dark:text-slate-400">Write scopes</dd></div>
                <div><dt className="text-2xl font-semibold">Local</dt><dd className="mt-1 text-xs text-slate-500 dark:text-slate-400">Tenant processing</dd></div>
              </dl>
            </section>

            <section aria-label="Product preview" className="relative mx-auto w-full max-w-2xl lg:mx-0">
              <div className="absolute -inset-4 -z-10 rotate-2 rounded-[2rem] bg-[#d9f99d]/45 dark:bg-[#d9f99d]/10" />
              <div className="overflow-hidden rounded-[1.35rem] border border-slate-200/80 bg-[#fbfcfa] shadow-[0_32px_80px_rgba(26,50,45,0.16)] dark:border-white/10 dark:bg-[#121b19] dark:shadow-black/30">
                <div className="flex items-center justify-between border-b border-slate-200 px-5 py-4 dark:border-white/10">
                  <div><p className="text-sm font-semibold">Tenant posture</p><p className="mt-0.5 text-xs text-slate-600 dark:text-slate-300">Last review · just now</p></div>
                  <span className="border border-emerald-200 bg-emerald-50 px-2.5 py-1 text-xs font-semibold text-emerald-700 dark:border-emerald-700/40 dark:bg-emerald-900/20 dark:text-emerald-300">Connected</span>
                </div>
                <div className="grid grid-cols-3 divide-x divide-slate-200 border-b border-slate-200 dark:divide-white/10 dark:border-white/10">
                  {[['184', 'Policies'], ['37', 'Groups'], ['08', 'Conflicts']].map(([value, label]) => (
                    <div key={label} className="p-5 sm:p-6"><p className="text-2xl font-semibold tabular-nums sm:text-3xl">{value}</p><p className="mt-1 text-xs text-slate-600 dark:text-slate-300">{label}</p></div>
                  ))}
                </div>
                <div className="p-5 sm:p-6">
                  <div className="mb-5 flex items-end justify-between"><div><p className="text-sm font-semibold">Policy distribution</p><p className="mt-1 text-xs text-slate-600 dark:text-slate-300">Active configurations by family</p></div><span className="text-xs font-medium text-[#147d72] dark:text-[#6ee7d8]">Review all</span></div>
                  <div className="space-y-4">
                    {[['Settings catalog', '74', '78%'], ['Device configuration', '52', '56%'], ['Endpoint security', '31', '38%'], ['Compliance', '27', '29%']].map(([label, count, width]) => (
                      <div key={label} className="grid grid-cols-[minmax(0,1fr)_2.5rem] items-center gap-4">
                        <div><div className="mb-1.5 flex justify-between text-xs"><span>{label}</span><span className="text-slate-400">{count}</span></div><div className="h-1.5 bg-slate-100 dark:bg-white/10"><div className="h-full bg-[#147d72]" style={{ width }} /></div></div>
                        <span className="text-right font-mono text-[10px] text-slate-400">{width}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </section>
          </div>
        </main>
      )}

      {/* Authenticated — show tabs and content */}
      {auth?.isAuthenticated && (
        <>
          <nav aria-label="Primary" className="border-b border-slate-200 bg-white/70 dark:border-white/10 dark:bg-white/[0.025]">
            <div className="mx-auto max-w-[1440px] overflow-x-auto px-4 sm:px-6 lg:px-10">
              <div className="flex min-w-max gap-6 sm:gap-8">
                {tabs.map((tab) => (
                  <button
                    key={tab.key}
                    onClick={() => !tab.disabled && setActiveTab(tab.key)}
                    disabled={tab.disabled}
                    aria-current={activeTab === tab.key ? 'page' : undefined}
                    className={`group relative items-center gap-2.5 border-b-2 py-4 text-sm font-semibold transition ${tab.disabled ? 'hidden sm:flex' : 'flex'} ${
                      activeTab === tab.key
                        ? 'border-[#147d72] text-[#125f58] dark:border-[#6ee7d8] dark:text-[#6ee7d8]'
                        : tab.disabled
                          ? 'cursor-not-allowed border-transparent text-slate-300 dark:text-slate-700'
                          : 'border-transparent text-slate-600 hover:border-slate-300 hover:text-slate-900 dark:text-slate-300 dark:hover:border-slate-600 dark:hover:text-white'
                    }`}
                  >
                    <span aria-hidden="true" className="hidden font-mono text-[10px] sm:inline">{tab.marker}</span>
                    <span className="hidden sm:inline">{tab.label}</span><span className="sm:hidden">{tab.shortLabel}</span>
                    {tab.disabled && (
                      <span className="ml-0.5 border border-slate-200 px-1.5 py-0.5 text-[9px] uppercase tracking-wider text-slate-400 dark:border-white/10 dark:text-slate-500">
                        Soon
                      </span>
                    )}
                  </button>
                ))}
              </div>
            </div>
          </nav>

          <main id="main-content" className="mx-auto max-w-[1440px] px-4 py-8 sm:px-6 lg:px-10 lg:py-10">
            {activeTab === 'dashboard' && (
              <Dashboard
                policies={policies}
                groups={groups}
                loading={dataLoading}
                onRefresh={handleRefresh}
                onOpenConflicts={() => setActiveTab('conflicts')}
                loadedAt={dataLoadedAt}
                fromCache={fromCache}
              />
            )}
            {activeTab === 'groupExplorer' && (
              <GroupExplorer policies={policies} groups={groups} />
            )}
            {activeTab === 'conflicts' && (
              <ConflictAnalyzer policies={policies} groups={groups} />
            )}
            {activeTab === 'optimization' && (
              <Optimization
                key={authCacheKey}
                policies={policies}
                groups={groups}
                isReady={authCacheKey !== null && loadedForKey === authCacheKey}
                loading={dataLoading}
              />
            )}
          </main>
        </>
      )}
    </div>
  )
}
