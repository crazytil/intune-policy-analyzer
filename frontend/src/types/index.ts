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

export type OptimizationPlatform = 'windows' | 'macos' | 'ios' | 'android' | 'linux'

export interface OptimizationPolicyPreview {
  policyId: string
  policyName: string
  policyType: string
  platform: string | null
  settingCount: number
  affectedSettings: string[]
}

export interface OptimizationFinding {
  findingId: string
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

export interface OptimizationAnalysisResult {
  summary: {
    totalFindings: number
    consolidationCandidates: number
    fragmentationHotspots: number
    domains: string[]
    platforms: string[]
  }
  findings: OptimizationFinding[]
}

export interface PolicyTypeInfo {
  key: string
  label: string
  icon: string
}

export const POLICY_TYPES: PolicyTypeInfo[] = [
  { key: 'deviceConfiguration', label: 'Device Configuration', icon: 'DC' },
  { key: 'settingsCatalog', label: 'Settings Catalog', icon: 'SC' },
  { key: 'compliance', label: 'Compliance', icon: 'CP' },
  { key: 'complianceV2', label: 'Compliance v2', icon: 'C2' },
  { key: 'appProtection', label: 'App Protection', icon: 'AP' },
  { key: 'appConfiguration', label: 'App Configuration', icon: 'AC' },
  { key: 'endpointSecurity', label: 'Endpoint Security', icon: 'ES' },
  { key: 'conditionalAccess', label: 'Conditional Access', icon: 'CA' },
  { key: 'autopilot', label: 'Autopilot', icon: 'AU' },
  { key: 'powershellScripts', label: 'PowerShell Scripts', icon: 'PS' },
  { key: 'remediationScripts', label: 'Remediation Scripts', icon: 'RM' },
  { key: 'groupPolicy', label: 'Group Policy (ADMX)', icon: 'GP' },
]
