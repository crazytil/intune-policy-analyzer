export interface Policy {
  id: string
  displayName: string
  description: string | null
  policyType: string
  platform: string | null
  created: string | null
  modified: string | null
  settings: unknown[]
  assignments: unknown[]
  raw: unknown
}

export interface Group {
  id: string
  displayName: string
  description: string | null
  memberCount: number | null
  groupTypes: string[]
  membershipRule: string | null
}

export interface GroupPolicyMapping {
  group: Group
  policies: Policy[]
  assignmentSource: string
}

export interface AuthStatus {
  isAuthenticated: boolean
  userName: string | null
  tenantId: string | null
}

export interface OptimizationPolicyPreview {
  policyId: string
  policyName: string
  policyType: string
  platform: string | null
  settingCount: number
}

export interface OptimizationFinding {
  recommendationType: 'consolidationCandidate' | 'fragmentationHotspot'
  title: string
  summary: string
  rationale: string
  domain: string
  audience: string
  platforms: string[]
  confidenceScore: number
  impactScore: number
  policyCount: number
  sharedSettingCount: number
  uniqueSettingCount: number
  matchingSettingCount: number
  conflictCount: number
  exampleSettings: string[]
  policies: OptimizationPolicyPreview[]
}

export interface OptimizationSummary {
  totalFindings: number
  consolidationCandidates: number
  fragmentationHotspots: number
  domains: string[]
  platforms: string[]
}

export interface OptimizationAnalysisResult {
  summary: OptimizationSummary
  findings: OptimizationFinding[]
}

export interface PolicyTypeInfo {
  key: string
  label: string
  icon: string
}

export const POLICY_TYPES: PolicyTypeInfo[] = [
  { key: 'deviceConfiguration', label: 'Device Configuration', icon: '⚙️' },
  { key: 'settingsCatalog', label: 'Settings Catalog', icon: '📋' },
  { key: 'compliance', label: 'Compliance', icon: '✅' },
  { key: 'complianceV2', label: 'Compliance v2', icon: '✅' },
  { key: 'appProtection', label: 'App Protection', icon: '🛡️' },
  { key: 'appConfiguration', label: 'App Configuration', icon: '📱' },
  { key: 'endpointSecurity', label: 'Endpoint Security', icon: '🔒' },
  { key: 'conditionalAccess', label: 'Conditional Access', icon: '🚪' },
  { key: 'autopilot', label: 'Autopilot', icon: '✈️' },
  { key: 'powershellScripts', label: 'PowerShell Scripts', icon: '📜' },
  { key: 'remediationScripts', label: 'Remediation Scripts', icon: '🔧' },
  { key: 'groupPolicy', label: 'Group Policy (ADMX)', icon: '🏛️' },
]
