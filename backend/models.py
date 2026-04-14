from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


def _to_camel(name: str) -> str:
    parts = name.split("_")
    return parts[0] + "".join(w.capitalize() for w in parts[1:])


class PolicyType(str, Enum):
    DEVICE_CONFIGURATION = "deviceConfiguration"
    SETTINGS_CATALOG = "settingsCatalog"
    COMPLIANCE = "compliance"
    COMPLIANCE_V2 = "complianceV2"
    APP_PROTECTION = "appProtection"
    APP_CONFIGURATION = "appConfiguration"
    ENDPOINT_SECURITY = "endpointSecurity"
    CONDITIONAL_ACCESS = "conditionalAccess"
    AUTOPILOT = "autopilot"
    POWERSHELL_SCRIPTS = "powershellScripts"
    REMEDIATION_SCRIPTS = "remediationScripts"
    GROUP_POLICY_ADMX = "groupPolicyAdmx"


class AssignmentType(str, Enum):
    INCLUDE = "include"
    EXCLUDE = "exclude"


class AssignmentSource(str, Enum):
    DIRECT = "direct"
    INHERITED = "inherited"
    ALL_USERS = "all_users"
    ALL_DEVICES = "all_devices"


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingType(str, Enum):
    ORPHANED = "orphaned"
    UNUSED = "unused"
    BROAD = "broad"
    CONSOLIDATION = "consolidation"
    REDUNDANT = "redundant"


class PolicyAssignment(BaseModel):
    model_config = ConfigDict(alias_generator=_to_camel, populate_by_name=True)
    id: str | None = None
    target: dict[str, Any] = Field(default_factory=dict)


class Policy(BaseModel):
    model_config = ConfigDict(alias_generator=_to_camel, populate_by_name=True)
    id: str
    display_name: str = ""
    description: str | None = None
    policy_type: PolicyType
    platform: str | None = None
    created: datetime | None = None
    modified: datetime | None = None
    settings: list[dict[str, Any]] = Field(default_factory=list)
    assignments: list[dict[str, Any]] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class Group(BaseModel):
    model_config = ConfigDict(alias_generator=_to_camel, populate_by_name=True)
    id: str
    display_name: str = ""
    description: str | None = None
    member_count: int | None = None
    group_types: list[str] = Field(default_factory=list)
    membership_rule: str | None = None


class GroupPolicyMapping(BaseModel):
    model_config = ConfigDict(alias_generator=_to_camel, populate_by_name=True)
    group: Group
    policies: list[Policy] = Field(default_factory=list)
    assignment_source: AssignmentSource


class ConflictPolicy(BaseModel):
    model_config = ConfigDict(alias_generator=_to_camel, populate_by_name=True)
    policy_id: str
    policy_name: str
    policy_type: str
    value: Any = None
    value_display: str = ""


class ConflictItem(BaseModel):
    model_config = ConfigDict(alias_generator=_to_camel, populate_by_name=True)
    setting_key: str
    setting_label: str = ""
    has_different_values: bool = False
    policies: list[ConflictPolicy] = Field(default_factory=list)


class OptimizationFinding(BaseModel):
    model_config = ConfigDict(alias_generator=_to_camel, populate_by_name=True)
    finding_type: FindingType
    severity: Severity
    description: str
    recommendation: str
    affected_policies: list[dict[str, Any]] = Field(default_factory=list)


class AuthStatus(BaseModel):
    model_config = ConfigDict(alias_generator=_to_camel, populate_by_name=True)
    is_authenticated: bool = False
    user_name: str | None = None
    tenant_id: str | None = None
