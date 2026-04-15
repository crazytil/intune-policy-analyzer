from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable, Optional

from conflict_analyzer import (
    _extract_settings,
    _filter_policies_by_platforms,
    _get_assigned_group_ids,
    _platform_bucket_key,
    _platform_tokens,
)
from models import (
    OptimizationAnalysisResult,
    OptimizationFindingV1,
    OptimizationPolicyPreview,
    OptimizationRecommendationType,
    OptimizationSummary,
    Policy,
)


# ── CSP area → logical domain mapping ────────────────────────────────────────
#
# This maps the official Microsoft Policy CSP area names (from the URI path
# ./Device/Vendor/MSFT/Policy/Config/{Area}/...) to logical groupings.
# Source: https://learn.microsoft.com/windows/client-management/mdm/policy-configuration-service-provider
#
# Only areas that share a clear functional domain are merged; everything else
# keeps its own domain name to avoid false groupings.

_CSP_AREA_TO_DOMAIN: dict[str, str] = {
    # ── Defender / Endpoint Security ─────────────────────────────────────
    "defender": "Defender",
    "admx_microsoftdefenderantivirus": "Defender",
    "windowsdefendersecuritycenter": "Defender Security Center",
    "webthreatdefense": "Web Threat Defense",
    "exploitguard": "Exploit Guard",
    "attacksurfacereduction": "Attack Surface Reduction",
    # ── SmartScreen ──────────────────────────────────────────────────────
    "smartscreen": "SmartScreen",
    # ── Firewall ─────────────────────────────────────────────────────────
    "firewall": "Firewall",
    # ── BitLocker / Encryption ───────────────────────────────────────────
    "bitlocker": "BitLocker",
    "dataprotection": "Data Protection",
    # ── Windows Update ───────────────────────────────────────────────────
    "update": "Windows Update",
    "deliveryoptimization": "Windows Update",
    "admx_servicing": "Windows Update",
    # ── Device Security / Hardware ───────────────────────────────────────
    "deviceguard": "Device Guard",
    "virtualizationbasedtechnology": "Device Guard",
    "dmaguard": "DMA Guard",
    "secureboot": "Secure Boot",
    "tpm": "TPM",
    "admx_tpm": "TPM",
    "lsa": "LSA Protection",
    "admx_credentialproviders": "Credential Providers",
    "admx_credssp": "Credential Providers",
    "credentialproviders": "Credential Providers",
    "credentialsdelegation": "Credential Providers",
    "credentialsui": "Credential Providers",
    "admx_credui": "Credential Providers",
    # ── Identity & Authentication ────────────────────────────────────────
    "authentication": "Authentication",
    "devicelock": "Device Lock",
    "admx_kerberos": "Kerberos",
    "kerberos": "Kerberos",
    "admx_sam": "Authentication",
    "admx_logon": "Windows Logon",
    "windowslogon": "Windows Logon",
    "admx_ctrlaltdel": "Windows Logon",
    "admx_winlogon": "Windows Logon",
    "federatedauthentication": "Federated Authentication",
    # ── Browser ──────────────────────────────────────────────────────────
    "browser": "Edge (Legacy)",
    "admx_microsoftedge": "Edge",
    "microsoft_edge": "Edge",
    "microsoftedge": "Edge",
    "admx_internetexplorer": "Internet Explorer",
    "internetexplorer": "Internet Explorer",
    # ── Connectivity ─────────────────────────────────────────────────────
    "wifi": "WiFi",
    "admx_wlansvc": "WiFi",
    "bluetooth": "Bluetooth",
    "cellular": "Cellular",
    "connectivity": "Connectivity",
    "admx_networkconnections": "Network",
    "networkisolation": "Network",
    "networklistmanager": "Network",
    "admx_dnsclient": "Network",
    "admx_wcm": "Network",
    "windowsconnectionmanager": "Network",
    "admx_lanmanserver": "Network",
    "admx_lanmanworkstation": "Network",
    "lanmanserver": "Network",
    "lanmanworkstation": "Network",
    "admx_tcpip": "Network",
    "admx_qos": "Network",
    "eap": "Network",
    "admx_iscsi": "Network",
    "wirelessdisplay": "Wireless Display",
    # ── Privacy & Telemetry ──────────────────────────────────────────────
    "privacy": "Privacy",
    "admx_datacollection": "Telemetry",
    "tenantdefinedtelemetry": "Telemetry",
    "devicehealthmonitoring": "Device Health Monitoring",
    "admx_icm": "Internet Communication",
    # ── Printing ─────────────────────────────────────────────────────────
    "printers": "Printing",
    "admx_printing": "Printing",
    "admx_printing2": "Printing",
    "enterprisecloudprint": "Printing",
    # ── Start Menu / Taskbar / Shell ─────────────────────────────────────
    "start": "Start Menu",
    "admx_startmenu": "Start Menu",
    "admx_taskbar": "Taskbar",
    "newsandinterests": "Taskbar",
    "stickers": "Start Menu",
    # ── Search ───────────────────────────────────────────────────────────
    "search": "Search",
    # ── Experience / UI ──────────────────────────────────────────────────
    "experience": "User Experience",
    "admx_desktop": "Desktop",
    "desktop": "Desktop",
    "display": "Display",
    "admx_controlpanel": "Control Panel",
    "admx_controlpaneldisplay": "Control Panel",
    "admx_cpls": "Control Panel",
    "settings": "Settings",
    "admx_globalization": "Globalization",
    "admx_windowsexplorer": "File Explorer",
    "admx_explorer": "File Explorer",
    "admx_framepanes": "File Explorer",
    "admx_shellcommandpromptregedittools": "Shell & Command Prompt",
    "textinput": "Text Input",
    "admx_tabletpcinputpanel": "Text Input",
    "admx_tabletshell": "Text Input",
    "handwriting": "Text Input",
    "timelanguagesettings": "Time & Language",
    "notifications": "Notifications",
    "admx_wpn": "Notifications",
    "multitasking": "Multitasking",
    "abovelock": "Lock Screen",
    "personalization": "Personalization",
    # ── Storage / USB ────────────────────────────────────────────────────
    "storage": "Storage",
    "admx_removablestorage": "Removable Storage",
    "admx_enhancedstorage": "Storage",
    "deviceinstallation": "Device Installation",
    "admx_deviceinstallation": "Device Installation",
    # ── Apps / Store ─────────────────────────────────────────────────────
    "applicationmanagement": "Application Management",
    "admx_windowsstore": "Microsoft Store",
    "admx_appxpackagemanager": "Application Management",
    "admx_appxruntime": "Application Management",
    "appruntime": "Application Management",
    "desktopappinstaller": "Application Management",
    "admx_programs": "Application Management",
    "appdeviceinventory": "Application Management",
    # ── Remote Desktop ───────────────────────────────────────────────────
    "remotedesktop": "Remote Desktop",
    "admx_terminalserver": "Remote Desktop",
    "remotedesktopservices": "Remote Desktop",
    "admx_remoteassistance": "Remote Assistance",
    "remoteassistance": "Remote Assistance",
    "remotemanagement": "Remote Management",
    "admx_windowsremotemanagement": "Remote Management",
    "remoteshell": "Remote Management",
    # ── Power ────────────────────────────────────────────────────────────
    "power": "Power",
    "admx_power": "Power",
    # ── Camera / Hardware restrictions ───────────────────────────────────
    "camera": "Camera",
    "admx_sensors": "Sensors",
    # ── Kiosk ────────────────────────────────────────────────────────────
    "kioskbrowser": "Kiosk",
    "admx_kioskbrowser": "Kiosk",
    "lockdown": "Kiosk",
    # ── Education ────────────────────────────────────────────────────────
    "education": "Education",
    # ── Local Security / Audit ───────────────────────────────────────────
    "localpoliciessecurityoptions": "Local Security Policy",
    "audit": "Audit",
    "admx_auditsettings": "Audit",
    "userrights": "User Rights",
    "localusersandgroups": "Local Users & Groups",
    "admx_restrictedgroups": "Local Users & Groups",
    "security": "Security",
    "admx_securitycenter": "Security",
    "admx_mssecurityguide": "Security",
    "admx_msslegacy": "Security",
    # ── System / Miscellaneous ───────────────────────────────────────────
    "system": "System",
    "admx_grouppolicy": "Group Policy",
    "admx_errorreporting": "Error Reporting",
    "errorreporting": "Error Reporting",
    "admx_eventlog": "Event Log",
    "admx_eventlogging": "Event Log",
    "eventlogservice": "Event Log",
    "admx_eventviewer": "Event Log",
    "admx_bits": "BITS",
    "bits": "BITS",
    "admx_scripts": "Scripts",
    "admx_msi": "Windows Installer",
    "admx_mdt": "Deployment",
    "windowsautopilot": "Autopilot",
    "admx_smartcard": "Smart Card",
    "speech": "Speech",
    "maps": "Maps",
    "admx_help": "Help",
    "admx_helpandsupport": "Help",
    "games": "Games",
    "licensing": "Licensing",
    "windowssandbox": "Windows Sandbox",
    "windowspowershell": "PowerShell",
    "admx_powershellexecutionpolicy": "PowerShell",
    "windowsai": "Windows AI",
    "windowsinkworkspace": "Windows Ink",
    "sudo": "Sudo",
    "mixedreality": "Mixed Reality",
    "clouddesktop": "Cloud Desktop",
    "messaging": "Messaging",
    "humanpresence": "Human Presence",
    "settingssync": "Settings Sync",
    "admx_settingssync": "Settings Sync",
    "cryptography": "Cryptography",
    "admx_ciphersuiteorder": "Cryptography",
    "admx_offlinefiles": "Offline Files",
    "admx_folderredirection": "Folder Redirection",
    "appvirtualization": "App Virtualization",
    "admx_userexperiencevirtualization": "App Virtualization",
    "tenantrestrictions": "Tenant Restrictions",
    "troubleshooting": "Troubleshooting",
    "admx_msdt": "Troubleshooting",
    "taskmanager": "Task Manager",
    "taskscheduler": "Task Scheduler",
    "admx_sdiageng": "Troubleshooting",
    "admx_sdiagschd": "Troubleshooting",
    "memorydump": "Memory Dump",
    "filesystem": "File System",
    "admx_filesys": "File System",
    "servicecontrolmanager": "Service Control Manager",
    "systemservices": "System Services",
    "datausage": "Data Usage",
    "remoteprocedurecall": "RPC",
    "admx_rpc": "RPC",
    "admx_dcom": "DCOM",
    "admx_attachmentmanager": "Attachment Manager",
    "attachmentmanager": "Attachment Manager",
    "admx_com": "COM",
    "admx_dfs": "DFS",
    "admx_activexinstallservice": "ActiveX",
    "activexcontrols": "ActiveX",
    "admx_snmp": "SNMP",
    "admx_pca": "Program Compatibility",
    "admx_appcompat": "Program Compatibility",
    "admx_devicecompat": "Program Compatibility",
    "admx_pushtoinstall": "Push to Install",
    "admx_encryptfilesonmove": "EFS",
    "admx_hotspotauth": "Hotspot Authentication",
    "controlpolicyconflict": "Policy Conflict",
    "admx_wdi": "Diagnostics",
    "admx_performancediagnostics": "Diagnostics",
    "admx_diskdiagnostic": "Diagnostics",
    "admx_leakdiagnostic": "Diagnostics",
    "admx_radar": "Diagnostics",
    "admx_reliability": "Diagnostics",
    "admx_kdc": "KDC",
    "admx_nca": "Network Connectivity Assistant",
    "admx_ncsi": "Network Connectivity Status",
    "admx_w32time": "Windows Time",
    "admx_wininit": "Windows Init",
    "admx_winsrv": "Windows Services",
    "admx_windowsconnectnow": "Network",
    "admx_peertopeerecaching": "BranchCache",
    "admx_sharing": "Sharing",
    "admx_distributedlinktracking": "Distributed Link Tracking",
    "admx_dwm": "Desktop Window Manager",
    "admx_eaime": "IME",
    "admx_wordwheel": "Search",
    "admx_mmcsnapins": "MMC",
    "admx_mmc": "MMC",
    "admx_servermanager": "Server Manager",
    "admx_fthsvc": "Fault Tolerant Heap",
    "admx_windowscolorsystem": "Color Management",
    "admx_disknvcache": "Disk Cache",
    "admx_diskquota": "Disk Quota",
    "admx_soundrec": "Sound",
    "admx_linklayertopologydiscovery": "Network",
    "admx_userprofiles": "User Profiles",
    "admx_touchinput": "Touch Input",
    "admx_windowsmediadrm": "Windows Media",
    "admx_windowsmediaplayer": "Windows Media",
    "admx_systemrestore": "System Restore",
    "admx_srmfci": "File Classification",
    "admx_fileservervssprovider": "File Server",
    "admx_admpwd": "LAPS",
    "admx_filerecovery": "File Recovery",
    "admx_msifilerecovery": "File Recovery",
    "admx_filerevocation": "File Revocation",
    "admx_locationprovideradm": "Location",
    "admx_devicesetup": "Device Setup",
    "admx_externalboot": "External Boot",
    "admx_msapolicy": "MSA Policy",
    "admx_pentraining": "Pen Training",
    "admx_mobilepcmobilitycenter": "Mobility Center",
    "admx_mobilepcpresentationsettings": "Presentation Settings",
    "admx_netlogon": "Netlogon",
    "admx_msched": "Maintenance Scheduler",
    "admx_windowsinkworkspace": "Windows Ink",
    "admx_wincal": "Windows Calendar",
    "admx_iis": "IIS",
}

# ── Office ADMX areas (from M365 Apps ADMX templates) ────────────────────────
# Definition IDs for Office ADMX settings follow the pattern:
#   {product}~policy~l_{productarea}...
# e.g. "office16v2~policy~l_microsoftofficeword", "office16v2~policy~l_microsoftofficepowerpoint"
# These are NOT Windows CSP areas — they come from the Office ADMX templates
# ingested into the Settings Catalog.

_OFFICE_ADMX_PRODUCT_DOMAINS: dict[str, str] = {
    "l_microsoftofficeword": "Office — Word",
    "l_microsoftofficeexcel": "Office — Excel",
    "l_microsoftofficepowerpoint": "Office — PowerPoint",
    "l_microsoftofficeoutlook": "Office — Outlook",
    "l_microsoftofficeaccess": "Office — Access",
    "l_microsoftofficeonenote": "Office — OneNote",
    "l_microsoftofficepublisher": "Office — Publisher",
    "l_microsoftofficevisio": "Office — Visio",
    "l_microsoftofficeproject": "Office — Project",
    "l_microsoftofficeinfopath": "Office — InfoPath",
    "l_microsoftoffice": "Office — Common",
    "l_microsoftlync": "Office — Teams/Lync",
    "l_microsoftgroove": "Office — OneDrive for Business",
    "l_microsoftonedriveforbusiness": "Office — OneDrive for Business",
    "l_outlookmobile": "Office — Outlook Mobile",
}

# ── Legacy device configuration property prefix → domain ─────────────────────
# For DeviceConfiguration policies (windows10GeneralConfiguration etc.), the
# property names use camelCase prefixes that indicate the functional area.
# These must be matched from longest to most specific first.

_LEGACY_PROPERTY_PREFIX_RULES: tuple[tuple[str, str], ...] = (
    ("defenderCloudBlockLevel", "Defender"),
    ("defenderPotentiallyUnwantedAppAction", "Defender"),
    ("defenderSubmitSamplesConsentType", "Defender"),
    ("defenderRequireRealTimeMonitoring", "Defender"),
    ("defenderScheduledScanTime", "Defender"),
    ("defenderScanType", "Defender"),
    ("defenderEnabled", "Defender"),
    ("bitLocker", "BitLocker"),
    ("firewall", "Firewall"),
    ("edge", "Edge"),
    ("password", "Device Lock"),
    ("storageRequire", "Data Protection"),
    ("securityBlock", "Compliance"),
    ("deviceThreatProtection", "Threat Protection"),
    ("osMinimum", "OS Version"),
    ("osMaximum", "OS Version"),
    ("earlyLaunchAntiMalwareDriver", "Boot Security"),
    ("secureBootEnabled", "Secure Boot"),
    ("codeIntegrityEnabled", "Code Integrity"),
    ("tpmRequired", "TPM"),
    ("activeFirewallRequired", "Firewall"),
    ("antiSpywareRequired", "Defender"),
    ("antivirusRequired", "Defender"),
    ("realTimeProtectionEnabled", "Defender"),
    ("signatureOutOfDate", "Defender"),
    ("rtpEnabled", "Defender"),
    ("avEnabled", "Defender"),
    ("windowsHealthMonitoring", "Device Health Monitoring"),
    ("cameraBlocked", "Camera"),
    ("cellularBlock", "Cellular"),
    ("bluetoothBlocked", "Bluetooth"),
    ("nfcBlocked", "NFC"),
    ("wifiBlock", "WiFi"),
    ("wifiBlocked", "WiFi"),
    ("screenCaptureBlocked", "Screen Capture"),
    ("diagnosticDataBlockSubmission", "Telemetry"),
    ("locationServicesBlocked", "Privacy"),
    ("appsBlock", "Application Management"),
    ("experienceBlock", "User Experience"),
    ("startBlock", "Start Menu"),
    ("windowsSpotlight", "Lock Screen"),
    ("windowsStore", "Microsoft Store"),
    ("searchBlock", "Search"),
    ("searchDisable", "Search"),
    ("updateServiceUrl", "Windows Update"),
    ("settingsBlock", "Settings"),
    ("internetSharingBlocked", "Network"),
    ("configurationProfileBlockChanges", "Compliance"),
    ("compliantAppsList", "Compliance"),
)

# ── Conditional Access ───────────────────────────────────────────────────────
_CA_DOMAIN = "Conditional Access"

_PLATFORM_LABELS = {
    "windows": "Windows",
    "macos": "macOS",
    "ios": "iOS/iPadOS",
    "android": "Android",
    "linux": "Linux",
    "unknown": "Unknown",
    "all": "All Platforms",
}


def _extract_csp_area(path: str) -> str | None:
    """Extract the CSP area name from a URI path or definition_id.

    Settings Catalog keys look like:
      settingsCatalog:./Device/Vendor/MSFT/Policy/Config/Defender/AllowArchiveScanning
      settingsCatalog:./User/Vendor/MSFT/Policy/Config/MicrosoftEdge/Startup/HomepageLocation

    The area is the segment after Config/ (position varies slightly).
    """
    segments = [s for s in path.replace("\\", "/").split("/") if s and s != "."]
    # Find "Config" segment and take the next one as area
    for i, seg in enumerate(segments):
        if seg.lower() == "config" and i + 1 < len(segments):
            return segments[i + 1]
    return None


def _extract_admx_domain_from_definition_id(definition_id: str) -> str | None:
    """Extract domain from ADMX-style definition IDs.

    Formats:
      microsoft_edge~policy~microsoft_edge~ContentSettings,DefaultCookiesSetting
        → area = "microsoft_edge"
      office16v2~policy~l_microsoftofficeword~...
        → area = "l_microsoftofficeword" → "Office — Word"
      admx_microsoftdefenderantivirus~...
        → area = "admx_microsoftdefenderantivirus" → via CSP lookup
    """
    if "~" not in definition_id:
        return None

    parts = definition_id.split("~")
    # Format: {source}~policy~{area}~{category},...
    # The area is typically parts[2]
    if len(parts) >= 3:
        area = parts[2].lower().strip()

        # Check Office ADMX products first (most specific)
        for marker, domain in _OFFICE_ADMX_PRODUCT_DOMAINS.items():
            if area == marker:
                return domain

        # For Microsoft Edge, the area is "microsoft_edge"
        if area in _CSP_AREA_TO_DOMAIN:
            return _CSP_AREA_TO_DOMAIN[area]

        # Try the source (parts[0]) for ADMX-backed Windows settings
        source = parts[0].lower().strip()
        if source in _CSP_AREA_TO_DOMAIN:
            return _CSP_AREA_TO_DOMAIN[source]

    return None


def _classify_domain(setting_key: str, display_name: str) -> str:
    """Classify a setting into a functional domain using structured parsing.

    The classification uses the actual setting key structure rather than
    substring matching to avoid false groupings. Priority order:

    1. CSP URI path extraction (most reliable for Settings Catalog)
    2. ADMX definition ID parsing (for ADMX-backed policies)
    3. Definition ID prefix matching (for underscore-delimited IDs)
    4. Legacy property prefix matching (for Device Configuration)
    5. Conditional Access detection
    """
    # Split the setting key into prefix:path
    colon_idx = setting_key.find(":")
    if colon_idx < 0:
        return "Other"

    prefix = setting_key[:colon_idx]
    path = setting_key[colon_idx + 1:]

    # ── Conditional Access ───────────────────────────────────────────────
    if prefix == "conditionalAccess":
        return _CA_DOMAIN

    # ── Settings Catalog / Compliance V2 / Endpoint Security ─────────────
    if prefix in ("settingsCatalog", "complianceV2", "endpointSecurity"):
        # Try CSP URI path first (e.g., ./Device/Vendor/MSFT/Policy/Config/Defender/...)
        csp_area = _extract_csp_area(path)
        if csp_area:
            area_lower = csp_area.lower()
            if area_lower in _CSP_AREA_TO_DOMAIN:
                return _CSP_AREA_TO_DOMAIN[area_lower]
            # ADMX areas often appear as the CSP area (e.g., "ADMX_StartMenu")
            admx_key = f"admx_{area_lower}"
            if admx_key in _CSP_AREA_TO_DOMAIN:
                return _CSP_AREA_TO_DOMAIN[admx_key]
            # Return the CSP area name itself as the domain (title-cased)
            return csp_area

        # Try ADMX-style definition ID (contains ~)
        admx_domain = _extract_admx_domain_from_definition_id(path)
        if admx_domain:
            return admx_domain

        # Try underscore-delimited definition ID
        # e.g., device_vendor_msft_policy_config_defender_allowarchivescanning
        # or device_vendor_msft_defender_...
        path_lower = path.lower()
        underscore_parts = path_lower.split("_")

        # Find "config" segment in underscore-delimited path
        for i, part in enumerate(underscore_parts):
            if part == "config" and i + 1 < len(underscore_parts):
                area = underscore_parts[i + 1]
                if area in _CSP_AREA_TO_DOMAIN:
                    return _CSP_AREA_TO_DOMAIN[area]
                return area.title()

        # Check if it starts with a known CSP area pattern
        # e.g., "device_vendor_msft_defender_..." → "defender"
        for area, domain in _CSP_AREA_TO_DOMAIN.items():
            if area in underscore_parts:
                return domain

        return "Other"

    # ── Legacy Device Configuration ──────────────────────────────────────
    if prefix in ("deviceConfiguration", "compliance"):
        # path format: "windows10GeneralConfiguration|propertyName"
        # or just "propertyName" for some types
        pipe_idx = path.find("|")
        prop = path[pipe_idx + 1:] if pipe_idx >= 0 else path

        for prop_prefix, domain in _LEGACY_PROPERTY_PREFIX_RULES:
            if prop.startswith(prop_prefix):
                return domain

        return "Other"

    # ── Group Policy ADMX ────────────────────────────────────────────────
    if prefix == "groupPolicyAdmx":
        admx_domain = _extract_admx_domain_from_definition_id(path)
        if admx_domain:
            return admx_domain
        return "Group Policy"

    # ── App Protection / App Configuration / Autopilot ───────────────────
    if prefix == "appProtection":
        return "App Protection"
    if prefix == "appConfiguration":
        return "App Configuration"
    if prefix == "autopilot":
        return "Autopilot"

    return "Other"


def _platform_labels(platform_key: str) -> list[str]:
    labels = [_PLATFORM_LABELS.get(token, token.title()) for token in platform_key.split("|") if token]
    return labels or ["Unknown"]


def _audience_targets(
    policy: Policy,
    group_name_by_id: Optional[dict[str, str]] = None,
) -> list[tuple[str, str]]:
    targets: list[tuple[str, str]] = []
    for assignment in policy.assignments:
        target = assignment.get("target", {})
        odata_type = str(target.get("@odata.type", ""))
        group_id = str(target.get("groupId", "")).strip()
        if group_id and "exclusion" not in odata_type.lower():
            targets.append((f"group:{group_id}", group_name_by_id.get(group_id, group_id) if group_name_by_id else group_id))
        elif "allLicensedUsers" in odata_type:
            targets.append(("all_users", "All Users"))
        elif "allDevices" in odata_type:
            targets.append(("all_devices", "All Devices"))

    if not targets:
        for synthetic in _get_assigned_group_ids(policy):
            if synthetic == "__ALL__":
                targets.append(("all_assigned", "All Assigned"))
            else:
                targets.append((
                    f"group:{synthetic}",
                    group_name_by_id.get(synthetic, synthetic) if group_name_by_id else synthetic,
                ))
    return targets


def _filter_clusters_by_group_audience(
    clusters: dict[tuple[str, str, str, str], dict[str, Any]],
    selected_group_id: Optional[str],
) -> dict[tuple[str, str, str, str], dict[str, Any]]:
    if not selected_group_id:
        return clusters
    expected_audience_key = f"group:{selected_group_id}"
    return {
        cluster_key: cluster
        for cluster_key, cluster in clusters.items()
        if cluster_key[1] == expected_audience_key
    }


def _score_cluster(
    *,
    policy_count: int,
    shared_setting_count: int,
    unique_setting_count: int,
    conflict_count: int,
) -> tuple[int, int]:
    impact = min(100, policy_count * 18 + unique_setting_count * 8 + shared_setting_count * 10)
    confidence = 40 + policy_count * 10 + shared_setting_count * 12 - conflict_count * 15
    if unique_setting_count >= 3:
        confidence += 5
    return max(0, min(100, confidence)), max(0, impact)


def _make_policy_preview(policy: Policy, settings: list[dict[str, Any]]) -> OptimizationPolicyPreview:
    return OptimizationPolicyPreview(
        policy_id=policy.id,
        policy_name=policy.display_name,
        policy_type=policy.policy_type.value,
        platform=next(iter(_platform_labels(_platform_bucket_key(policy))), policy.platform),
        setting_count=len(settings),
        affected_settings=sorted({
            entry.get("display_name") or entry["setting_key"]
            for entry in settings
        }),
    )


def _finding_id(
    recommendation_type: OptimizationRecommendationType,
    domain: str,
    audience: str,
    platform_key: str,
    policies: list[Policy],
) -> str:
    policy_signature = ",".join(sorted(policy.id for policy in policies))
    return "|".join((recommendation_type.value, domain, audience, platform_key, policy_signature))


def _make_finding(
    *,
    recommendation_type: OptimizationRecommendationType,
    domain: str,
    audience: str,
    platform_key: str,
    policies: list[Policy],
    policy_settings: dict[str, list[dict[str, Any]]],
    shared_setting_count: int,
    matching_setting_count: int,
    conflict_count: int,
) -> OptimizationFindingV1:
    unique_setting_keys = {
        entry["setting_key"]
        for policy in policies
        for entry in policy_settings[policy.id]
    }
    unique_setting_count = len(unique_setting_keys)
    confidence_score, impact_score = _score_cluster(
        policy_count=len(policies),
        shared_setting_count=shared_setting_count,
        unique_setting_count=unique_setting_count,
        conflict_count=conflict_count,
    )

    top_settings = sorted(
        {
            entry.get("display_name") or entry["setting_key"]
            for policy in policies
            for entry in policy_settings[policy.id]
        }
    )[:5]
    policy_previews = [_make_policy_preview(policy, policy_settings[policy.id]) for policy in policies]
    title = (
        f"Consolidate {domain} policies for {audience}"
        if recommendation_type == OptimizationRecommendationType.CONSOLIDATION_CANDIDATE
        else f"Reduce {domain} policy fragmentation for {audience}"
    )
    summary = (
        f"{len(policies)} policies target the same audience on {', '.join(_platform_labels(platform_key))}."
    )
    rationale = (
        f"{shared_setting_count} shared exact settings, {conflict_count} conflicts, "
        f"{unique_setting_count} total exact settings in this domain cluster."
    )

    return OptimizationFindingV1(
        finding_id=_finding_id(recommendation_type, domain, audience, platform_key, policies),
        recommendation_type=recommendation_type,
        title=title,
        summary=summary,
        rationale=rationale,
        domain=domain,
        audience=audience,
        platforms=_platform_labels(platform_key),
        confidence_score=confidence_score,
        impact_score=impact_score,
        policy_count=len(policies),
        shared_setting_count=shared_setting_count,
        unique_setting_count=unique_setting_count,
        matching_setting_count=matching_setting_count,
        conflict_count=conflict_count,
        example_settings=top_settings,
        policies=policy_previews,
    )


def _iter_domain_clusters(
    policies: Iterable[Policy],
    group_name_by_id: Optional[dict[str, str]] = None,
) -> dict[tuple[str, str, str, str], dict[str, Any]]:
    clusters: dict[tuple[str, str, str, str], dict[str, Any]] = {}

    for policy in policies:
        policy_entries = _extract_settings(policy)
        if not policy_entries:
            continue

        by_domain: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for entry in policy_entries:
            domain = _classify_domain(entry["setting_key"], entry.get("display_name", ""))
            by_domain[domain].append(entry)

        for audience_key, audience_label in _audience_targets(policy, group_name_by_id):
            for domain, entries in by_domain.items():
                cluster_key = (
                    domain,
                    audience_key,
                    _platform_bucket_key(policy),
                    policy.policy_type.value,
                )
                cluster = clusters.setdefault(
                    cluster_key,
                    {
                        "domain": domain,
                        "audience": audience_label,
                        "platform_key": _platform_bucket_key(policy),
                        "policy_type": policy.policy_type.value,
                        "policies": {},
                    },
                )
                cluster["policies"][policy.id] = {
                    "policy": policy,
                    "settings": entries,
                }

    return clusters


def analyze_optimization_opportunities(
    policies: list[Policy],
    selected_platforms: Optional[set[str]] = None,
    selected_group_id: Optional[str] = None,
    group_name_by_id: Optional[dict[str, str]] = None,
) -> OptimizationAnalysisResult:
    filtered_policies = _filter_policies_by_platforms(policies, selected_platforms)
    clusters = _iter_domain_clusters(filtered_policies, group_name_by_id)
    clusters = _filter_clusters_by_group_audience(clusters, selected_group_id)
    findings: list[OptimizationFindingV1] = []

    for (domain, _audience_key, platform_key, _policy_type), cluster in clusters.items():
        if domain == "Other":
            continue

        policy_map = cluster["policies"]
        if len(policy_map) < 2:
            continue

        policies_in_cluster = [entry["policy"] for entry in policy_map.values()]
        policy_settings = {
            policy_id: entry["settings"]
            for policy_id, entry in policy_map.items()
        }

        settings_map: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for entries in policy_settings.values():
            for setting in entries:
                settings_map[setting["setting_key"]].append(setting)

        shared_setting_count = 0
        matching_setting_count = 0
        conflict_count = 0
        for entries in settings_map.values():
            if len(entries) < 2:
                continue
            shared_setting_count += 1
            distinct_values = {repr(entry["value"]) for entry in entries}
            if len(distinct_values) > 1:
                conflict_count += 1
            else:
                matching_setting_count += 1

        unique_setting_count = len(settings_map)
        recommendation_type: OptimizationRecommendationType | None = None
        if conflict_count == 0 and shared_setting_count >= 1:
            recommendation_type = OptimizationRecommendationType.CONSOLIDATION_CANDIDATE
        elif len(policies_in_cluster) >= 3 and unique_setting_count >= 3:
            recommendation_type = OptimizationRecommendationType.FRAGMENTATION_HOTSPOT

        if recommendation_type is None:
            continue

        findings.append(
            _make_finding(
                recommendation_type=recommendation_type,
                domain=domain,
                audience=cluster["audience"],
                platform_key=platform_key,
                policies=sorted(policies_in_cluster, key=lambda policy: policy.display_name.lower()),
                policy_settings=policy_settings,
                shared_setting_count=shared_setting_count,
                matching_setting_count=matching_setting_count,
                conflict_count=conflict_count,
            )
        )

    findings.sort(
        key=lambda finding: (
            -finding.confidence_score,
            -finding.impact_score,
            finding.domain,
            finding.audience,
        )
    )

    summary = OptimizationSummary(
        total_findings=len(findings),
        consolidation_candidates=sum(
            1
            for finding in findings
            if finding.recommendation_type == OptimizationRecommendationType.CONSOLIDATION_CANDIDATE
        ),
        fragmentation_hotspots=sum(
            1
            for finding in findings
            if finding.recommendation_type == OptimizationRecommendationType.FRAGMENTATION_HOTSPOT
        ),
        domains=sorted({finding.domain for finding in findings}),
        platforms=sorted({platform for finding in findings for platform in finding.platforms}),
    )
    return OptimizationAnalysisResult(summary=summary, findings=findings)
