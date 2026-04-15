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
const CACHE_BACKGROUND_REFRESH_AGE_MS = 5 * 60 * 1000 // 5 minutes

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

function timeAgo(timestamp: number): string {
  const seconds = Math.floor((Date.now() - timestamp) / 1000)
  if (seconds < 60) return 'just now'
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ${minutes % 60}m ago`
  return new Date(timestamp).toLocaleString()
}

function Spinner({ className = 'h-4 w-4' }: { className?: string }) {
  return (
    <svg className={`animate-spin ${className}`} viewBox="0 0 24 24" fill="none">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
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
        const cacheTimestamp = Math.min(cachedPolicies.timestamp, cachedGroups.timestamp)
        commitLoadedData(
          cachedPolicies.data,
          cachedGroups.data,
          cacheTimestamp,
          true,
        )
        if (Date.now() - cacheTimestamp > CACHE_BACKGROUND_REFRESH_AGE_MS) {
          void queueBackgroundRefresh()
        }
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
    try {
      const status = await login()
      setAuth(status)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Login failed')
    }
  }

  const handleLogout = async () => {
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
    }
  }

  const tabs: { key: Tab; label: string; disabled: boolean }[] = [
    { key: 'dashboard', label: 'Dashboard', disabled: false },
    { key: 'groupExplorer', label: 'Group Explorer', disabled: false },
    { key: 'conflicts', label: 'Conflict Analyser', disabled: false },
    { key: 'optimization', label: 'Optimisation', disabled: false },
  ]

  const dataLoaded = policies.length > 0

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100 transition-colors">
      {/* Header */}
      <header className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-3">
              <span className="text-xl font-bold tracking-tight">
                📊 Intune Policy Analyser
              </span>
              {/* Cache/refresh indicator in header */}
              {auth?.isAuthenticated && dataLoaded && (
                <div className="hidden sm:flex items-center gap-2 ml-4">
                  {fromCache && (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-yellow-50 dark:bg-yellow-900/20 text-yellow-600 dark:text-yellow-400 text-xs font-medium rounded">
                      ⚡ Cached
                    </span>
                  )}
                  {dataLoadedAt && (
                    <span className="text-xs text-gray-400 dark:text-gray-500">
                      {timeAgo(dataLoadedAt)}
                    </span>
                  )}
                  <button
                    onClick={handleRefresh}
                    disabled={dataLoading}
                    className="inline-flex items-center gap-1 px-2 py-1 text-xs text-gray-500 dark:text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 hover:bg-gray-100 dark:hover:bg-gray-700 rounded transition-colors disabled:opacity-50"
                    title="Refresh policies and groups from Intune"
                  >
                    {dataLoading ? <Spinner /> : <span>↻</span>}
                    Refresh
                  </button>
                </div>
              )}
            </div>

            <div className="flex items-center gap-4">
              {/* Auth status */}
              {authLoading ? (
                <span className="text-sm text-gray-400">Checking auth…</span>
              ) : auth?.isAuthenticated ? (
                <div className="flex items-center gap-3">
                  <span className="text-sm text-gray-600 dark:text-gray-300">
                    {auth.userName}
                  </span>
                  {auth.tenantId && (
                    <span className="text-xs bg-gray-100 dark:bg-gray-700 text-gray-500 dark:text-gray-400 px-2 py-0.5 rounded font-mono">
                      {auth.tenantId}
                    </span>
                  )}
                  <button
                    onClick={handleLogout}
                    className="text-sm text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
                  >
                    Sign out
                  </button>
                </div>
              ) : (
                <button
                  onClick={handleLogin}
                  className="px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 transition-colors"
                >
                  Sign in with Microsoft
                </button>
              )}

              {/* Dark mode toggle */}
              <button
                onClick={() => setDarkMode(!darkMode)}
                className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
                aria-label="Toggle dark mode"
              >
                {darkMode ? '☀️' : '🌙'}
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Error banner */}
      {error && (
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mt-4">
          <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 px-4 py-3 rounded-lg flex items-center justify-between">
            <span className="text-sm">{error}</span>
            <button
              onClick={() => setError(null)}
              className="text-red-500 hover:text-red-700 dark:hover:text-red-300"
            >
              ✕
            </button>
          </div>
        </div>
      )}

      {/* Not authenticated — landing page */}
      {!authLoading && !auth?.isAuthenticated && (
        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-24 text-center">
          <h2 className="text-3xl font-bold mb-4">Welcome to Intune Policy Analyser</h2>
          <p className="text-gray-500 dark:text-gray-400 mb-8 max-w-lg mx-auto">
            Analyse your Intune policies, explore group assignments, detect conflicts, and optimise your configuration — all read-only, no app registration required.
          </p>
          <button
            onClick={handleLogin}
            className="px-6 py-3 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 transition-colors text-lg"
          >
            Sign in with Microsoft
          </button>
        </main>
      )}

      {/* Authenticated — show tabs and content */}
      {auth?.isAuthenticated && (
        <>
          <nav className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
              <div className="flex gap-1">
                {tabs.map((tab) => (
                  <button
                    key={tab.key}
                    onClick={() => !tab.disabled && setActiveTab(tab.key)}
                    disabled={tab.disabled}
                    className={`px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
                      activeTab === tab.key
                        ? 'border-blue-600 text-blue-600 dark:text-blue-400 dark:border-blue-400'
                        : tab.disabled
                          ? 'border-transparent text-gray-300 dark:text-gray-600 cursor-not-allowed'
                          : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 hover:border-gray-300'
                    }`}
                  >
                    {tab.label}
                    {tab.disabled && (
                      <span className="ml-1.5 text-xs bg-gray-100 dark:bg-gray-700 text-gray-400 dark:text-gray-500 px-1.5 py-0.5 rounded">
                        Soon
                      </span>
                    )}
                  </button>
                ))}
              </div>
            </div>
          </nav>

          <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
            {activeTab === 'dashboard' && (
              <Dashboard
                policies={policies}
                groups={groups}
                loading={dataLoading}
                onRefresh={handleRefresh}
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
              <Optimization isReady={dataLoaded} groups={groups} />
            )}
          </main>
        </>
      )}
    </div>
  )
}
