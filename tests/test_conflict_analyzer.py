from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from conflict_analyzer import (
    _extract_settings,
    _format_value_display,
    _format_value_path,
    _resolve_catalog_setting_key,
    _resolve_catalog_value_display,
    analyze_all_conflicts,
)
from models import Policy, PolicyType


class ConflictAnalyzerFormattingTests(unittest.TestCase):
    def test_formats_settings_catalog_path_from_definition_id(self) -> None:
        self.assertEqual(
            _format_value_path("settingsCatalog:device_vendor_msft_policy_config_defender_allowfullscanremovabledrivescanning"),
            "Settings Catalog > Defender > Allow Full Scan Removable Drives Scanning",
        )

    def test_formats_settings_catalog_enum_value_to_human_text(self) -> None:
        self.assertEqual(
            _format_value_display("device_vendor_msft_policy_config_defender_allowarchivescanning_1"),
            "Enabled",
        )

    def test_formats_settings_catalog_enum_value_with_named_prefix(self) -> None:
        self.assertEqual(
            _format_value_display("device_vendor_msft_policy_config_defender_submitsamplesconsent_3"),
            "Submit Samples Consent: Option 3",
        )

    def test_uses_definition_base_uri_and_offset_uri_for_setting_key(self) -> None:
        setting = {
            "settingDefinitions": [
                {
                    "id": "device_vendor_msft_policy_config_defender_allowarchivescanning",
                    "baseUri": "./Device/Vendor/MSFT/Policy/Config/Defender",
                    "offsetUri": "AllowArchiveScanning",
                }
            ]
        }
        self.assertEqual(
            _resolve_catalog_setting_key(
                setting,
                "device_vendor_msft_policy_config_defender_allowarchivescanning",
                "settingsCatalog",
            ),
            "settingsCatalog:./Device/Vendor/MSFT/Policy/Config/Defender/AllowArchiveScanning",
        )

    def test_uses_definition_options_for_value_display(self) -> None:
        definition = {
            "options": [
                {
                    "displayName": "Send safe samples automatically",
                    "optionValue": {
                        "value": "device_vendor_msft_policy_config_defender_submitsamplesconsent_1"
                    },
                }
            ]
        }
        self.assertEqual(
            _resolve_catalog_value_display(
                {},
                definition,
                {"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"},
                "device_vendor_msft_policy_config_defender_submitsamplesconsent_1",
            ),
            "Send safe samples automatically",
        )

    def test_uses_option_item_id_for_value_display(self) -> None:
        definition = {
            "options": [
                {
                    "itemId": "device_vendor_msft_bitlocker_fixeddrivesrequireencryption_1",
                    "displayName": "Enabled",
                    "optionValue": {"value": 1},
                }
            ]
        }
        self.assertEqual(
            _resolve_catalog_value_display(
                {},
                definition,
                {"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"},
                "device_vendor_msft_bitlocker_fixeddrivesrequireencryption_1",
            ),
            "Enabled",
        )

    def test_formats_group_setting_children(self) -> None:
        setting = {
            "settingDefinitions": [
                {
                    "id": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficeapplicationsfromcreatingexecutablecontent",
                    "displayName": "Block Office applications from creating executable content",
                    "options": [
                        {
                            "itemId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficeapplicationsfromcreatingexecutablecontent_block",
                            "displayName": "Block",
                            "optionValue": {"value": "block"},
                        }
                    ],
                }
            ]
        }
        instance = {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingInstance",
            "groupSettingValue": {
                "children": [
                    {
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                        "settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficeapplicationsfromcreatingexecutablecontent",
                        "choiceSettingValue": {
                            "value": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficeapplicationsfromcreatingexecutablecontent_block"
                        },
                    }
                ]
            },
        }
        self.assertEqual(
            _resolve_catalog_value_display(
                setting,
                None,
                instance,
                {"children": []},
            ),
            "Block Office applications from creating executable content: Block",
        )

    def test_formats_group_setting_collection_children(self) -> None:
        setting = {
            "settingDefinitions": [
                {
                    "id": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutionofpotentiallyobfuscatedscripts",
                    "displayName": "Block execution of potentially obfuscated scripts",
                    "options": [
                        {
                            "itemId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutionofpotentiallyobfuscatedscripts_block",
                            "displayName": "Block",
                            "optionValue": {"value": "abc=1"},
                        }
                    ],
                }
            ]
        }
        instance = {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance",
            "groupSettingCollectionValue": [
                {
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutionofpotentiallyobfuscatedscripts",
                            "choiceSettingValue": {
                                "value": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutionofpotentiallyobfuscatedscripts_block"
                            },
                        }
                    ]
                }
            ],
        }
        self.assertEqual(
            _resolve_catalog_value_display(
                setting,
                None,
                instance,
                [{"children": []}],
            ),
            "Block execution of potentially obfuscated scripts: Block",
        )


class ConflictAnalyzerBehaviorTests(unittest.TestCase):
    def test_does_not_extract_script_metadata_as_settings(self) -> None:
        remediation_policy = Policy(
            id="script-1",
            display_name="Remediation One",
            policy_type=PolicyType.REMEDIATION_SCRIPTS,
            platform="windows",
            assignments=[{"target": {"groupId": "group-1"}}],
            raw={
                "runAs32Bit": True,
                "runAsAccount": "system",
                "publisher": "Admin",
                "fileName": "detect.ps1",
            },
        )

        self.assertEqual(_extract_settings(remediation_policy), [])

    def test_does_not_compare_policies_across_different_platforms(self) -> None:
        windows_policy = Policy(
            id="win-1",
            display_name="Windows Policy",
            policy_type=PolicyType.SETTINGS_CATALOG,
            platform="windows",
            assignments=[{"target": {"groupId": "group-1"}}],
            settings=[
                {
                    "settingInstance": {
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                        "settingDefinitionId": "device_vendor_msft_policy_config_defender_allowarchivescanning",
                        "choiceSettingValue": {"value": "enabled"},
                    },
                    "settingDefinitions": [
                        {
                            "id": "device_vendor_msft_policy_config_defender_allowarchivescanning",
                            "displayName": "Allow Archive Scanning",
                            "baseUri": "./Device/Vendor/MSFT/Policy/Config/Defender",
                            "offsetUri": "AllowArchiveScanning",
                        }
                    ],
                }
            ],
        )
        ios_policy = Policy(
            id="ios-1",
            display_name="iOS Policy",
            policy_type=PolicyType.SETTINGS_CATALOG,
            platform="iOS",
            assignments=[{"target": {"groupId": "group-1"}}],
            settings=[
                {
                    "settingInstance": {
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                        "settingDefinitionId": "device_vendor_msft_policy_config_defender_allowarchivescanning",
                        "choiceSettingValue": {"value": "disabled"},
                    },
                    "settingDefinitions": [
                        {
                            "id": "device_vendor_msft_policy_config_defender_allowarchivescanning",
                            "displayName": "Allow Archive Scanning",
                            "baseUri": "./Device/Vendor/MSFT/Policy/Config/Defender",
                            "offsetUri": "AllowArchiveScanning",
                        }
                    ],
                }
            ],
        )

        self.assertEqual(analyze_all_conflicts([windows_policy, ios_policy]), [])

    def test_ignores_device_configuration_certificate_profile_metadata(self) -> None:
        certificate_policy = Policy(
            id="cert-1",
            display_name="Trusted Root Certificate",
            policy_type=PolicyType.DEVICE_CONFIGURATION,
            platform="windows",
            assignments=[{"target": {"groupId": "group-1"}}],
            raw={
                "@odata.type": "#microsoft.graph.windows81TrustedRootCertificate",
                "destinationStore": "computerCertStoreRoot",
                "trustedRootCertificate": "BASE64",
                "certFileName": "corp-root.cer",
            },
        )

        self.assertEqual(_extract_settings(certificate_policy), [])

    def test_skips_matching_default_like_device_configuration_values(self) -> None:
        control_panel_policy = Policy(
            id="dc-1",
            display_name="Control Panel Policy",
            policy_type=PolicyType.DEVICE_CONFIGURATION,
            platform="windows",
            assignments=[{"target": {"groupId": "group-1"}}],
            raw={
                "@odata.type": "#microsoft.graph.windows10GeneralConfiguration",
                "bluetoothBlocked": False,
            },
        )
        wallpaper_policy = Policy(
            id="dc-2",
            display_name="Wallpaper Policy",
            policy_type=PolicyType.DEVICE_CONFIGURATION,
            platform="windows",
            assignments=[{"target": {"groupId": "group-1"}}],
            raw={
                "@odata.type": "#microsoft.graph.windows10GeneralConfiguration",
                "bluetoothBlocked": False,
            },
        )

        self.assertEqual(analyze_all_conflicts([control_panel_policy, wallpaper_policy]), [])

    def test_does_not_match_raw_device_configuration_fields_across_different_schemas(self) -> None:
        policy_a = Policy(
            id="dc-a",
            display_name="Policy A",
            policy_type=PolicyType.DEVICE_CONFIGURATION,
            platform="windows",
            assignments=[{"target": {"groupId": "group-1"}}],
            raw={
                "@odata.type": "#microsoft.graph.windows10GeneralConfiguration",
                "passwordRequired": True,
            },
        )
        policy_b = Policy(
            id="dc-b",
            display_name="Policy B",
            policy_type=PolicyType.DEVICE_CONFIGURATION,
            platform="windows",
            assignments=[{"target": {"groupId": "group-1"}}],
            raw={
                "@odata.type": "#microsoft.graph.windowsKioskConfiguration",
                "passwordRequired": False,
            },
        )

        self.assertEqual(analyze_all_conflicts([policy_a, policy_b]), [])

    def test_ignores_wifi_profile_payloads(self) -> None:
        wifi_policy = Policy(
            id="wifi-1",
            display_name="Corp WiFi",
            policy_type=PolicyType.DEVICE_CONFIGURATION,
            platform="windows",
            assignments=[{"target": {"groupId": "group-1"}}],
            raw={
                "@odata.type": "#microsoft.graph.windowsWifiEnterpriseEAPConfiguration",
                "ssid": "CorpWiFi",
                "networkName": "Corp WiFi",
            },
        )

        self.assertEqual(_extract_settings(wifi_policy), [])

    def test_ignores_custom_oma_profile_payloads(self) -> None:
        oma_policy = Policy(
            id="oma-1",
            display_name="Custom OMA",
            policy_type=PolicyType.DEVICE_CONFIGURATION,
            platform="windows",
            assignments=[{"target": {"groupId": "group-1"}}],
            raw={
                "@odata.type": "#microsoft.graph.windows10CustomConfiguration",
                "omaSettings": [
                    {
                        "displayName": "Policy/Config/Area/Setting",
                        "omaUri": "./Vendor/MSFT/Policy/Config/Area/Setting",
                        "value": "1",
                    }
                ],
            },
        )

        self.assertEqual(_extract_settings(oma_policy), [])


if __name__ == "__main__":
    unittest.main()
