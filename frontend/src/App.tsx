import { useState, useEffect, useCallback } from 'react'
import type { AuthStatus, Policy } from './types'
import { getAuthStatus, login, logout, fetchPolicies } from './services/api'
import Dashboard from './components/Dashboard'
import GroupExplorer from './components/GroupExplorer'
import ConflictAnalyzer from './components/ConflictAnalyzer'

type Tab = 'dashboard' | 'groupExplorer' | 'conflicts' | 'optimization'

const CACHE_KEY = 'intune-policies-cache'

interface PolicyCache {
  tenantId: string
  userName: string
  policies: Policy[]
  timestamp: number
}

function loadCachedPolicies(tenantId: string, userName: string): PolicyCache | null {
  try {
    const raw = sessionStorage.getItem(CACHE_KEY)
    if (!raw) return null
    const cache: PolicyCache = JSON.parse(raw)
    if (cache.tenantId === tenantId && cache.userName === userName && cache.policies.length > 0) {
      return cache
    }
  } catch { /* ignore */ }
  return null
}

function savePoliciesCache(tenantId: string, userName: string, policies: Policy[]) {
  try {
    const cache: PolicyCache = { tenantId, userName, policies, timestamp: Date.now() }
    sessionStorage.setItem(CACHE_KEY, JSON.stringify(cache))
  } catch { /* ignore - storage full */ }
}

function clearPoliciesCache() {
  try { sessionStorage.removeItem(CACHE_KEY) } catch { /* ignore */ }
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
  const [policies, setPolicies] = useState<Policy[]>([])
  const [policiesLoading, setPoliciesLoading] = useState(false)
  const [policiesLoadedAt, setPoliciesLoadedAt] = useState<number | null>(null)
  const [fromCache, setFromCache] = useState(false)
  const [error, setError] = useState<string | null>(null)

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

  // Auto-load policies when authenticated: try cache first, then fetch
  useEffect(() => {
    if (auth?.isAuthenticated && policies.length === 0 && !policiesLoading) {
      const cached = loadCachedPolicies(auth.tenantId ?? '', auth.userName ?? '')
      if (cached) {
        setPolicies(cached.policies)
        setPoliciesLoadedAt(cached.timestamp)
        setFromCache(true)
      } else {
        handleLoadPolicies()
      }
    }
  }, [auth?.isAuthenticated]) // eslint-disable-line react-hooks/exhaustive-deps

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
      setPoliciesLoadedAt(null)
      clearPoliciesCache()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Logout failed')
    }
  }

  const handleLoadPolicies = useCallback(async () => {
    setPoliciesLoading(true)
    setFromCache(false)
    setError(null)
    try {
      const data = await fetchPolicies()
      setPolicies(data)
      const now = Date.now()
      setPoliciesLoadedAt(now)
      if (auth?.tenantId && auth?.userName) {
        savePoliciesCache(auth.tenantId, auth.userName, data)
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load policies')
    } finally {
      setPoliciesLoading(false)
    }
  }, [auth?.tenantId, auth?.userName])

  const tabs: { key: Tab; label: string; disabled: boolean }[] = [
    { key: 'dashboard', label: 'Dashboard', disabled: false },
    { key: 'groupExplorer', label: 'Group Explorer', disabled: false },
    { key: 'conflicts', label: 'Conflict Analyzer', disabled: false },
    { key: 'optimization', label: 'Optimization', disabled: true },
  ]

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100 transition-colors">
      {/* Header */}
      <header className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-3">
              <span className="text-xl font-bold tracking-tight">
                📊 Intune Policy Analyzer
              </span>
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
          <h2 className="text-3xl font-bold mb-4">Welcome to Intune Policy Analyzer</h2>
          <p className="text-gray-500 dark:text-gray-400 mb-8 max-w-lg mx-auto">
            Analyze your Intune policies, explore group assignments, detect conflicts, and optimize your configuration — all read-only, no app registration required.
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
                loading={policiesLoading}
                onLoadPolicies={handleLoadPolicies}
                loadedAt={policiesLoadedAt}
                fromCache={fromCache}
              />
            )}
            {activeTab === 'groupExplorer' && (
              <GroupExplorer policies={policies} />
            )}
            {activeTab === 'conflicts' && (
              <ConflictAnalyzer policies={policies} />
            )}
          </main>
        </>
      )}
    </div>
  )
}
