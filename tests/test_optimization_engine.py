from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from models import Policy, PolicyType
from optimization_engine import _classify_domain, analyze_optimization_opportunities


def _assignment(group_id: str) -> dict[str, object]:
    return {
        "target": {
            "@odata.type": "#microsoft.graph.groupAssignmentTarget",
            "groupId": group_id,
        }
    }


class OptimizationEngineTests(unittest.TestCase):
    def test_classifies_bluetooth_from_legacy_property(self) -> None:
        self.assertEqual(
            _classify_domain(
                "deviceConfiguration:windows10GeneralConfiguration|bluetoothBlocked",
                "Block Bluetooth",
            ),
            "Bluetooth",
        )

    def test_classifies_telemetry_from_legacy_property(self) -> None:
        self.assertEqual(
            _classify_domain(
                "deviceConfiguration:windows10GeneralConfiguration|diagnosticDataBlockSubmission",
                "Block Diagnostic Data Submission",
            ),
            "Telemetry",
        )

    def test_classifies_defender_from_csp_uri(self) -> None:
        self.assertEqual(
            _classify_domain(
                "settingsCatalog:./Device/Vendor/MSFT/Policy/Config/Defender/AllowArchiveScanning",
                "Allow Archive Scanning",
            ),
            "Defender",
        )

    def test_classifies_edge_from_admx_definition_id(self) -> None:
        self.assertEqual(
            _classify_domain(
                "settingsCatalog:microsoft_edge~policy~microsoft_edge~ContentSettings,DefaultCookiesSetting",
                "Default cookies setting",
            ),
            "Edge",
        )

    def test_classifies_office_word_from_admx_definition_id(self) -> None:
        self.assertEqual(
            _classify_domain(
                "settingsCatalog:office16v2~policy~l_microsoftofficeword~l_wordoptions,L_DisableAutoRecover",
                "Disable AutoRecover",
            ),
            "Office — Word",
        )

    def test_classifies_office_outlook_from_admx_definition_id(self) -> None:
        self.assertEqual(
            _classify_domain(
                "settingsCatalog:office16v2~policy~l_microsoftofficeoutlook~l_outlooksecurity,L_EnableRPCEncryption",
                "Enable RPC Encryption",
            ),
            "Office — Outlook",
        )

    def test_does_not_mix_office_with_device_guard(self) -> None:
        """Office and Device Guard settings must never be grouped together."""
        office_domain = _classify_domain(
            "settingsCatalog:office16v2~policy~l_microsoftoffice~l_security,L_MacroRuntimeScanScope",
            "Macro Runtime Scan Scope",
        )
        device_guard_domain = _classify_domain(
            "settingsCatalog:./Device/Vendor/MSFT/Policy/Config/DeviceGuard/EnableVirtualizationBasedSecurity",
            "Enable Virtualization Based Security",
        )
        self.assertNotEqual(office_domain, device_guard_domain)
        self.assertEqual(office_domain, "Office — Common")
        self.assertEqual(device_guard_domain, "Device Guard")

    def test_classifies_from_underscore_definition_id(self) -> None:
        self.assertEqual(
            _classify_domain(
                "settingsCatalog:device_vendor_msft_policy_config_defender_allowarchivescanning",
                "Allow Archive Scanning",
            ),
            "Defender",
        )

    def test_conditional_access_classified_separately(self) -> None:
        self.assertEqual(
            _classify_domain(
                "conditionalAccess:conditions.locations",
                "Locations",
            ),
            "Conditional Access",
        )

    def test_emits_consolidation_candidate_for_same_domain_same_audience(self) -> None:
        policies = [
            Policy(
                id="edge-1",
                display_name="Edge Baseline",
                policy_type=PolicyType.DEVICE_CONFIGURATION,
                platform="windows",
                assignments=[_assignment("group-1")],
                raw={
                    "edgeBlocked": False,
                    "edgeBlockPopups": True,
                },
            ),
            Policy(
                id="edge-2",
                display_name="Edge Hardening",
                policy_type=PolicyType.DEVICE_CONFIGURATION,
                platform="windows",
                assignments=[_assignment("group-1")],
                raw={
                    "edgeBlocked": False,
                    "edgeCookiePolicy": "block_third_party",
                },
            ),
        ]

        result = analyze_optimization_opportunities(
            policies,
            group_name_by_id={"group-1": "Windows Pilot Devices"},
        )

        self.assertEqual(result.summary.total_findings, 1)
        self.assertEqual(result.summary.consolidation_candidates, 1)
        finding = result.findings[0]
        self.assertEqual(finding.recommendation_type.value, "consolidationCandidate")
        self.assertEqual(finding.domain, "Edge")
        self.assertEqual(finding.audience, "Windows Pilot Devices")
        self.assertEqual(finding.platforms, ["Windows"])
        self.assertEqual(finding.policy_count, 2)
        self.assertEqual(finding.shared_setting_count, 1)
        self.assertEqual(finding.conflict_count, 0)
        self.assertEqual(sorted(policy.policy_id for policy in finding.policies), ["edge-1", "edge-2"])
        self.assertTrue(any("Edge" in setting for setting in finding.policies[0].affected_settings))

    def test_emits_fragmentation_hotspot_for_split_domain_cluster(self) -> None:
        policies = [
            Policy(
                id="def-1",
                display_name="Defender One",
                policy_type=PolicyType.DEVICE_CONFIGURATION,
                platform="windows",
                assignments=[_assignment("group-1")],
                raw={"defenderEnabled": True},
            ),
            Policy(
                id="def-2",
                display_name="Defender Two",
                policy_type=PolicyType.DEVICE_CONFIGURATION,
                platform="windows",
                assignments=[_assignment("group-1")],
                raw={"defenderRequireRealTimeMonitoring": True},
            ),
            Policy(
                id="def-3",
                display_name="Defender Three",
                policy_type=PolicyType.DEVICE_CONFIGURATION,
                platform="windows",
                assignments=[_assignment("group-1")],
                raw={"defenderCloudBlockLevel": "high"},
            ),
        ]

        result = analyze_optimization_opportunities(policies)

        self.assertEqual(result.summary.total_findings, 1)
        self.assertEqual(result.summary.fragmentation_hotspots, 1)
        finding = result.findings[0]
        self.assertEqual(finding.recommendation_type.value, "fragmentationHotspot")
        self.assertEqual(finding.domain, "Defender")
        self.assertEqual(finding.policy_count, 3)
        self.assertEqual(finding.shared_setting_count, 0)
        self.assertEqual(finding.unique_setting_count, 3)
        self.assertEqual(finding.conflict_count, 0)

    def test_does_not_merge_across_platforms(self) -> None:
        policies = [
            Policy(
                id="edge-win",
                display_name="Windows Edge",
                policy_type=PolicyType.DEVICE_CONFIGURATION,
                platform="windows",
                assignments=[_assignment("group-1")],
                raw={"edgeBlocked": False},
            ),
            Policy(
                id="edge-ios",
                display_name="iOS Edge",
                policy_type=PolicyType.DEVICE_CONFIGURATION,
                platform="ios",
                assignments=[_assignment("group-1")],
                raw={"edgeBlocked": False},
            ),
        ]

        result = analyze_optimization_opportunities(policies)

        self.assertEqual(result.summary.total_findings, 0)
        self.assertEqual(result.findings, [])

    def test_applies_platform_filter(self) -> None:
        policies = [
            Policy(
                id="edge-1",
                display_name="Edge One",
                policy_type=PolicyType.DEVICE_CONFIGURATION,
                platform="windows",
                assignments=[_assignment("group-1")],
                raw={"edgeBlocked": False, "edgeBlockPopups": True},
            ),
            Policy(
                id="edge-2",
                display_name="Edge Two",
                policy_type=PolicyType.DEVICE_CONFIGURATION,
                platform="windows",
                assignments=[_assignment("group-1")],
                raw={"edgeBlocked": False, "edgeCookiePolicy": "block_third_party"},
            ),
            Policy(
                id="ios-1",
                display_name="iOS Restrictions One",
                policy_type=PolicyType.DEVICE_CONFIGURATION,
                platform="ios",
                assignments=[_assignment("group-1")],
                raw={"cameraBlocked": True},
            ),
            Policy(
                id="ios-2",
                display_name="iOS Restrictions Two",
                policy_type=PolicyType.DEVICE_CONFIGURATION,
                platform="ios",
                assignments=[_assignment("group-1")],
                raw={"screenCaptureBlocked": True},
            ),
            Policy(
                id="ios-3",
                display_name="iOS Restrictions Three",
                policy_type=PolicyType.DEVICE_CONFIGURATION,
                platform="ios",
                assignments=[_assignment("group-1")],
                raw={"bluetoothBlocked": True},
            ),
        ]

        result = analyze_optimization_opportunities(policies, selected_platforms={"windows"})

        self.assertEqual(result.summary.total_findings, 1)
        self.assertTrue(all(platform == "Windows" for platform in result.findings[0].platforms))

    def test_applies_group_filter(self) -> None:
        policies = [
            Policy(
                id="edge-1",
                display_name="Edge One",
                policy_type=PolicyType.DEVICE_CONFIGURATION,
                platform="windows",
                assignments=[_assignment("group-1")],
                raw={"edgeBlocked": False, "edgeBlockPopups": True},
            ),
            Policy(
                id="edge-2",
                display_name="Edge Two",
                policy_type=PolicyType.DEVICE_CONFIGURATION,
                platform="windows",
                assignments=[_assignment("group-1")],
                raw={"edgeBlocked": False, "edgeCookiePolicy": "block_third_party"},
            ),
            Policy(
                id="defender-1",
                display_name="Defender One",
                policy_type=PolicyType.DEVICE_CONFIGURATION,
                platform="windows",
                assignments=[_assignment("group-2")],
                raw={"defenderEnabled": True},
            ),
            Policy(
                id="defender-2",
                display_name="Defender Two",
                policy_type=PolicyType.DEVICE_CONFIGURATION,
                platform="windows",
                assignments=[_assignment("group-2")],
                raw={"defenderEnabled": True, "defenderCloudBlockLevel": "high"},
            ),
        ]

        result = analyze_optimization_opportunities(
            policies,
            selected_group_id="group-1",
            group_name_by_id={"group-1": "Windows Pilot Devices", "group-2": "Defender Devices"},
        )

        self.assertEqual(result.summary.total_findings, 1)
        self.assertEqual(result.findings[0].audience, "Windows Pilot Devices")
        self.assertEqual(sorted(policy.policy_id for policy in result.findings[0].policies), ["edge-1", "edge-2"])

    def test_group_filter_limits_results_to_selected_group_audience(self) -> None:
        policies = [
            Policy(
                id="edge-1",
                display_name="Edge One",
                policy_type=PolicyType.DEVICE_CONFIGURATION,
                platform="windows",
                assignments=[
                    _assignment("group-1"),
                    {"target": {"@odata.type": "#microsoft.graph.allLicensedUsersAssignmentTarget"}},
                ],
                raw={"edgeBlocked": False, "edgeBlockPopups": True},
            ),
            Policy(
                id="edge-2",
                display_name="Edge Two",
                policy_type=PolicyType.DEVICE_CONFIGURATION,
                platform="windows",
                assignments=[
                    _assignment("group-1"),
                    {"target": {"@odata.type": "#microsoft.graph.allLicensedUsersAssignmentTarget"}},
                ],
                raw={"edgeBlocked": False, "edgeCookiePolicy": "block_third_party"},
            ),
        ]

        result = analyze_optimization_opportunities(
            policies,
            selected_group_id="group-1",
            group_name_by_id={"group-1": "Windows Pilot Devices"},
        )

        self.assertEqual(result.summary.total_findings, 1)
        self.assertEqual([finding.audience for finding in result.findings], ["Windows Pilot Devices"])

    def test_does_not_cluster_across_different_policy_types(self) -> None:
        policies = [
            Policy(
                id="catalog-1",
                display_name="Password Catalog",
                policy_type=PolicyType.SETTINGS_CATALOG,
                platform="windows",
                assignments=[_assignment("group-1")],
                settings=[
                    {
                        "settingInstance": {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_passwordpolicy_passwordrequired",
                            "choiceSettingValue": {"value": "enabled"},
                        },
                        "settingDefinitions": [
                            {
                                "id": "device_vendor_msft_policy_config_passwordpolicy_passwordrequired",
                                "displayName": "Require Password",
                                "baseUri": "./Device/Vendor/MSFT/Policy/Config/PasswordPolicy",
                                "offsetUri": "PasswordRequired",
                            }
                        ],
                    }
                ],
            ),
            Policy(
                id="compliance-1",
                display_name="Compliance Password",
                policy_type=PolicyType.COMPLIANCE,
                platform="windows",
                assignments=[_assignment("group-1")],
                raw={"passwordRequired": True},
            ),
            Policy(
                id="device-1",
                display_name="Device Password",
                policy_type=PolicyType.DEVICE_CONFIGURATION,
                platform="windows",
                assignments=[_assignment("group-1")],
                raw={"passwordRequiredToUnlockFromIdle": True},
            ),
        ]

        result = analyze_optimization_opportunities(policies)

        self.assertEqual(result.summary.total_findings, 0)

    def test_emits_distinct_finding_ids_for_same_visible_cluster_metadata(self) -> None:
        policies = [
            Policy(
                id="dc-edge-1",
                display_name="Device Config Edge One",
                policy_type=PolicyType.DEVICE_CONFIGURATION,
                platform="windows",
                assignments=[_assignment("group-1")],
                raw={"edgeCookiePolicy": "block_third_party", "edgeBlockPopups": True},
            ),
            Policy(
                id="dc-edge-2",
                display_name="Device Config Edge Two",
                policy_type=PolicyType.DEVICE_CONFIGURATION,
                platform="windows",
                assignments=[_assignment("group-1")],
                raw={"edgeCookiePolicy": "block_third_party", "edgeSendDoNotTrackHeader": True},
            ),
            Policy(
                id="catalog-edge-1",
                display_name="Settings Catalog Edge One",
                policy_type=PolicyType.SETTINGS_CATALOG,
                platform="windows",
                assignments=[_assignment("group-1")],
                settings=[
                    {
                        "settingInstance": {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "microsoft_edge~policy~microsoft_edge~ContentSettings,DefaultCookiesSetting",
                            "choiceSettingValue": {"value": "microsoft.graph.deviceManagementConfigurationChoiceSettingValue_1"},
                        },
                        "settingDefinitions": [
                            {
                                "id": "microsoft_edge~policy~microsoft_edge~ContentSettings",
                                "displayName": "Default cookies setting",
                                "baseUri": "./Device/Vendor/MSFT/Policy/Config/MicrosoftEdge/ContentSettings",
                                "offsetUri": "DefaultCookiesSetting",
                            }
                        ],
                    },
                    {
                        "settingInstance": {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "microsoft_edge~policy~microsoft_edge~Startup,RestoreOnStartup",
                            "choiceSettingValue": {"value": "microsoft.graph.deviceManagementConfigurationChoiceSettingValue_1"},
                        },
                        "settingDefinitions": [
                            {
                                "id": "microsoft_edge~policy~microsoft_edge~Startup",
                                "displayName": "Restore on startup",
                                "baseUri": "./Device/Vendor/MSFT/Policy/Config/MicrosoftEdge/Startup",
                                "offsetUri": "RestoreOnStartup",
                            }
                        ],
                    }
                ],
            ),
            Policy(
                id="catalog-edge-2",
                display_name="Settings Catalog Edge Two",
                policy_type=PolicyType.SETTINGS_CATALOG,
                platform="windows",
                assignments=[_assignment("group-1")],
                settings=[
                    {
                        "settingInstance": {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "microsoft_edge~policy~microsoft_edge~ContentSettings,DefaultCookiesSetting",
                            "choiceSettingValue": {"value": "microsoft.graph.deviceManagementConfigurationChoiceSettingValue_1"},
                        },
                        "settingDefinitions": [
                            {
                                "id": "microsoft_edge~policy~microsoft_edge~ContentSettings",
                                "displayName": "Default cookies setting",
                                "baseUri": "./Device/Vendor/MSFT/Policy/Config/MicrosoftEdge/ContentSettings",
                                "offsetUri": "DefaultCookiesSetting",
                            }
                        ],
                    },
                    {
                        "settingInstance": {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "microsoft_edge~policy~microsoft_edge~Startup,HomepageLocation",
                            "choiceSettingValue": {"value": "microsoft.graph.deviceManagementConfigurationChoiceSettingValue_1"},
                        },
                        "settingDefinitions": [
                            {
                                "id": "microsoft_edge~policy~microsoft_edge~Startup",
                                "displayName": "Homepage location",
                                "baseUri": "./Device/Vendor/MSFT/Policy/Config/MicrosoftEdge/Startup",
                                "offsetUri": "HomepageLocation",
                            }
                        ],
                    }
                ],
            ),
        ]

        result = analyze_optimization_opportunities(
            policies,
            group_name_by_id={"group-1": "Windows Pilot Devices"},
        )

        self.assertEqual(result.summary.total_findings, 2)
        self.assertEqual(len({finding.finding_id for finding in result.findings}), 2)

    def test_falls_back_to_group_id_when_name_is_unavailable(self) -> None:
        policies = [
            Policy(
                id="edge-1",
                display_name="Edge One",
                policy_type=PolicyType.DEVICE_CONFIGURATION,
                platform="windows",
                assignments=[_assignment("group-99")],
                raw={"edgeBlocked": False, "edgeBlockPopups": True},
            ),
            Policy(
                id="edge-2",
                display_name="Edge Two",
                policy_type=PolicyType.DEVICE_CONFIGURATION,
                platform="windows",
                assignments=[_assignment("group-99")],
                raw={"edgeBlocked": False, "edgeCookiePolicy": "block_third_party"},
            ),
        ]

        result = analyze_optimization_opportunities(policies, group_name_by_id={})

        self.assertEqual(result.summary.total_findings, 1)
        self.assertEqual(result.findings[0].audience, "group-99")

    def test_ignores_default_like_legacy_device_configuration_values(self) -> None:
        policies = [
            Policy(
                id="dc-1",
                display_name="Corp-Win11-Azure - Control Panel Policy",
                policy_type=PolicyType.DEVICE_CONFIGURATION,
                platform="windows",
                assignments=[_assignment("group-1")],
                raw={
                    "@odata.type": "#microsoft.graph.windows10GeneralConfiguration",
                    "bluetoothBlocked": False,
                    "diagnosticDataBlockSubmission": False,
                },
            ),
            Policy(
                id="dc-2",
                display_name="Wallpaper Policy",
                policy_type=PolicyType.DEVICE_CONFIGURATION,
                platform="windows",
                assignments=[_assignment("group-1")],
                raw={
                    "@odata.type": "#microsoft.graph.windows10GeneralConfiguration",
                    "bluetoothBlocked": False,
                    "diagnosticDataBlockSubmission": False,
                },
            ),
        ]

        result = analyze_optimization_opportunities(
            policies,
            group_name_by_id={"group-1": "Windows Devices"},
        )

        self.assertEqual(result.summary.total_findings, 0)


if __name__ == "__main__":
    unittest.main()
