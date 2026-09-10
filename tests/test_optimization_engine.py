from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from models import Policy, PolicyType
from optimization_engine import _classify_domain, analyze_optimization_opportunities


def assignment(group="pilot", *, exclude=False, filter_id=None):
    kind = "exclusionGroupAssignmentTarget" if exclude else "groupAssignmentTarget"
    target = {"@odata.type": f"#microsoft.graph.{kind}", "groupId": group}
    if filter_id:
        target.update(deviceAndAppManagementAssignmentFilterId=filter_id,
                      deviceAndAppManagementAssignmentFilterType="include")
    return {"target": target}


def policy(key, **overrides):
    data = dict(id=key, display_name=f"Policy {key}", policy_type=PolicyType.DEVICE_CONFIGURATION,
                platform="windows", assignments=[assignment()],
                raw={"@odata.type": "#microsoft.graph.windows10GeneralConfiguration",
                     "edgeBlockPopups": True})
    data.update(overrides)
    return Policy(**data)


def catalog(key, value=True, children=None):
    instance = {
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
        "settingDefinitionId": "device_vendor_msft_policy_config_defender_allowarchivescanning",
        "choiceSettingValue": {"value": value},
    }
    if children is not None:
        instance["choiceSettingValue"]["children"] = children
    return policy(key, policy_type=PolicyType.SETTINGS_CATALOG, raw={},
                  settings=[{"settingInstance": instance}])


class DomainTests(unittest.TestCase):
    def test_structured_domains_preserve_area_boundaries(self):
        cases = {
            "settingsCatalog:./Device/Vendor/MSFT/Policy/Config/Defender/AllowArchiveScanning": "Defender",
            "settingsCatalog:device_vendor_msft_policy_config_defender_allowarchivescanning": "Defender",
            "settingsCatalog:device_vendor_msft_policy_config_admx_microsoftdefenderantivirus_setting": "Defender",
            "settingsCatalog:device_vendor_msft_policy_config_admx_startmenu_setting": "Start Menu",
            "settingsCatalog:device_vendor_msft_policy_config_admx_unknownvendor_setting": "Other",
            "settingsCatalog:device_vendor_msft_unknown_defender_setting": "Other",
            "settingsCatalog:microsoft_edge~policy~microsoft_edge~ContentSettings,DefaultCookiesSetting": "Edge",
            "settingsCatalog:office16v2~policy~l_microsoftofficeword~l_wordoptions,L_DisableAutoRecover": "Office — Word",
            "settingsCatalog:./Device/Vendor/MSFT/Policy/Config/DeviceGuard/EnableVirtualizationBasedSecurity": "Device Guard",
            "settingsCatalog:./Device/Vendor/MSFT/BitLocker/RequireDeviceEncryption": "BitLocker",
            "deviceConfiguration:windows10GeneralConfiguration|bluetoothBlocked": "Bluetooth",
            "deviceConfiguration:windows10GeneralConfiguration|diagnosticDataBlockSubmission": "Telemetry",
        }
        for key, expected in cases.items():
            with self.subTest(key=key):
                self.assertEqual(_classify_domain(key, "Unrelated display name"), expected)


class OptimizationEngineTests(unittest.TestCase):
    def test_consolidation_has_exact_counts_and_named_audience(self):
        a, b = policy("a"), policy("b")
        a.raw["edgeCookiePolicy"] = "block_third_party"
        b.raw["edgeSendDoNotTrackHeader"] = True
        result = analyze_optimization_opportunities([a, b], group_name_by_id={"pilot": "Pilot devices"})
        self.assertEqual(result.summary.consolidation_candidates, 1)
        finding = result.findings[0]
        self.assertEqual((finding.audience, finding.platforms), ("Pilot devices", ["Windows"]))
        self.assertEqual((finding.policy_count, finding.shared_setting_count,
                          finding.matching_setting_count, finding.unique_setting_count,
                          finding.conflict_count), (2, 1, 1, 3, 0))
        self.assertEqual([p.policy_id for p in finding.policies], ["a", "b"])
        self.assertEqual([p.setting_count for p in finding.policies], [2, 2])

    def test_complete_assignments_must_match(self):
        differences = [
            [assignment(), assignment("extra")],
            [assignment(), assignment("exception", exclude=True)],
            [assignment(filter_id="filtered")],
            [{"target": {"@odata.type": "#microsoft.graph.allDevicesAssignmentTarget"}}],
            [assignment(), {"target": {"@odata.type": "#microsoft.graph.unknownTarget"}}],
        ]
        for assignments in differences:
            with self.subTest(assignments=assignments):
                self.assertEqual(analyze_optimization_opportunities(
                    [policy("a"), policy("b", assignments=assignments)]).findings, [])

    def test_filter_ids_and_modes_are_part_of_audience(self):
        a, b = policy("a", assignments=[assignment(filter_id="one")]), policy("b", assignments=[assignment(filter_id="two")])
        self.assertEqual(analyze_optimization_opportunities([a, b]).findings, [])
        b.assignments = copy.deepcopy(a.assignments)
        b.assignments[0]["target"]["deviceAndAppManagementAssignmentFilterType"] = "exclude"
        self.assertEqual(analyze_optimization_opportunities([a, b]).findings, [])

    def test_assignment_order_and_assignment_ids_do_not_matter(self):
        assignments = [assignment(filter_id="filter-one"), assignment("exception", exclude=True), assignment("second")]
        a, b = policy("a", assignments=assignments), policy("b", assignments=list(reversed(copy.deepcopy(assignments))))
        a.assignments[0]["id"] = "assignment-a"
        b.assignments[0]["id"] = "assignment-b"
        result = analyze_optimization_opportunities([a, b], selected_group_id="pilot")
        self.assertEqual(len(result.findings), 1)
        self.assertIn("exception", result.findings[0].audience)
        self.assertIn("filter-one", result.findings[0].audience)
        self.assertEqual(analyze_optimization_opportunities([a, b], selected_group_id="exception").findings, [])

    def test_group_filter_keeps_full_audience_and_does_not_duplicate_findings(self):
        assignments = [assignment(), assignment("second")]
        policies = [policy("a", assignments=assignments), policy("b", assignments=assignments)]
        all_results = analyze_optimization_opportunities(policies)
        filtered = analyze_optimization_opportunities(policies, selected_group_id="pilot")
        self.assertEqual(len(all_results.findings), 1)
        self.assertEqual(all_results.findings, filtered.findings)
        self.assertIn("second", filtered.findings[0].audience)

    def test_platform_family_schema_and_template_boundaries(self):
        for changed in (
            policy("b", platform="ios"),
            policy("b", platform=None),
            policy("b", policy_type=PolicyType.COMPLIANCE),
            policy("b", raw={"@odata.type": "#microsoft.graph.windowsKioskConfiguration", "edgeBlockPopups": True}),
        ):
            with self.subTest(policy=changed):
                self.assertEqual(analyze_optimization_opportunities([policy("a"), changed]).findings, [])
        a, b = catalog("a"), catalog("b")
        a.raw["templateReference"] = {"templateId": "template-a"}
        b.raw["templateReference"] = {"templateId": "template-b"}
        self.assertEqual(analyze_optimization_opportunities([a, b]).findings, [])
        self.assertEqual(analyze_optimization_opportunities([policy("a"), policy("b")], selected_platforms={"ios"}).findings, [])

    def test_false_defaults_are_not_evidence_but_false_conflicts_are_preserved(self):
        a, b = policy("a", raw={"bluetoothBlocked": False}), policy("b", raw={"bluetoothBlocked": False})
        self.assertEqual(analyze_optimization_opportunities([a, b]).findings, [])
        a, b = policy("a"), policy("b")
        a.raw["edgeCookiePolicy"], b.raw["edgeCookiePolicy"] = True, False
        self.assertEqual(analyze_optimization_opportunities([a, b]).findings, [])
        self.assertEqual(len(analyze_optimization_opportunities([catalog("a", False), catalog("b", False)]).findings), 1)

    def test_conflicts_outside_recommended_domain_block_consolidation(self):
        a, b = policy("a"), policy("b")
        a.raw["passwordRequired"], b.raw["passwordRequired"] = True, False
        self.assertEqual(analyze_optimization_opportunities([a, b]).findings, [])

    def test_choice_children_are_compared_not_just_parent_value(self):
        a = catalog("a", children=[{"settingDefinitionId": "child", "simpleSettingValue": {"value": 4}}])
        b = catalog("b", children=[{"settingDefinitionId": "child", "simpleSettingValue": {"value": 9}}])
        self.assertEqual(analyze_optimization_opportunities([a, b]).findings, [])

    def test_object_key_order_is_not_a_conflict(self):
        a, b = catalog("a", {"first": 1, "second": 2}), catalog("b", {"second": 2, "first": 1})
        self.assertEqual(len(analyze_optimization_opportunities([a, b]).findings), 1)

    def test_fragmentation_threshold_and_conflict_count(self):
        policies = [policy(str(i), raw={name: True}) for i, name in enumerate(
            ["defenderEnabled", "defenderRequireRealTimeMonitoring", "defenderScanType"])]
        self.assertEqual(analyze_optimization_opportunities(policies[:2]).findings, [])
        result = analyze_optimization_opportunities(policies)
        self.assertEqual(result.summary.fragmentation_hotspots, 1)
        finding = result.findings[0]
        self.assertEqual((finding.shared_setting_count, finding.unique_setting_count), (0, 3))
        policies[1].raw["defenderEnabled"] = False
        result = analyze_optimization_opportunities(policies)
        self.assertEqual(result.summary.fragmentation_hotspots, 1)
        self.assertEqual(result.findings[0].conflict_count, 1)

    def test_unsupported_or_incomplete_policies_are_not_candidates(self):
        cases = [dict(assignments=[]), dict(platform="unknown"), dict(raw={}),
                 dict(policy_type=PolicyType.CONDITIONAL_ACCESS, raw={"conditions": {"clientAppTypes": ["all"]}}),
                 dict(policy_type=PolicyType.GROUP_POLICY_ADMX, settings=[{"id": "setting", "enabled": True}])]
        for overrides in cases:
            with self.subTest(overrides=overrides):
                self.assertEqual(analyze_optimization_opportunities([policy("a", **overrides), policy("b", **overrides)]).findings, [])

    def test_duplicate_entries_in_one_policy_do_not_create_shared_evidence(self):
        a, b = catalog("a"), catalog("b")
        a.settings.append(copy.deepcopy(a.settings[0]))
        b.settings[0]["settingInstance"]["settingDefinitionId"] = "device_vendor_msft_policy_config_defender_other"
        self.assertEqual(analyze_optimization_opportunities([a, b]).findings, [])

    def test_catalog_with_missing_settings_is_not_a_candidate(self):
        a, b = catalog("a"), catalog("b")
        a.raw["settingCount"] = 2
        b.raw["settingCount"] = 2
        self.assertEqual(analyze_optimization_opportunities([a, b]).findings, [])

    def test_default_only_policy_is_not_included_in_other_policies_finding(self):
        a, b, c = policy("a"), policy("b"), policy("c")
        a.raw["edgeCookiePolicy"] = False
        b.raw["edgeCookiePolicy"] = False
        c.raw = {"@odata.type": "#microsoft.graph.windows10GeneralConfiguration", "edgeCookiePolicy": False}
        result = analyze_optimization_opportunities([a, b, c])
        self.assertEqual(len(result.findings), 1)
        self.assertEqual([item.policy_id for item in result.findings[0].policies], ["a", "b"])

    def test_identity_is_stable_across_order_and_group_rename(self):
        a, b = policy("a"), policy("b")
        first = analyze_optimization_opportunities([a, b], group_name_by_id={"pilot": "Old name"})
        second = analyze_optimization_opportunities([b, a], group_name_by_id={"pilot": "New name"})
        self.assertEqual(first.findings[0].finding_id, second.findings[0].finding_id)


if __name__ == "__main__":
    unittest.main()
