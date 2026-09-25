"""Field-map regressions for sparse and nested Cyble observable arrays."""

from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "source"))

from cyble_mapping import _explicit_ioc_candidates, _json_path_values


def candidates(alert, rule):
    return _explicit_ioc_candidates(alert, "iocs", {"default": {"ioc_rules": [rule]}})


class FieldMapTests(unittest.TestCase):
    def test_missing_type_does_not_inherit_an_email_siblings_type(self):
        alert = {"observables": [
            {"value": "example.invalid"},
            {"value": "someone@example.invalid", "type": "email"},
        ]}
        result = candidates(alert, {"value_path": "observables[*].value", "type_path": "observables[*].type"})
        self.assertEqual(result, [("example.invalid", None), ("someone@example.invalid", "excluded")])

    def test_missing_value_does_not_shift_a_later_values_type(self):
        alert = {"observables": [
            {"type": "email"},
            {"value": "example.invalid", "type": "domain"},
            {"value": "https://example.invalid/path", "type": "url"},
        ]}
        result = candidates(alert, {"value_path": "observables[*].value", "type_path": "observables[*].type"})
        self.assertEqual(result, [("example.invalid", "domain"), ("https://example.invalid/path", "url")])

    def test_nested_arrays_preserve_both_parent_and_child_indices(self):
        alert = {"groups": [
            {"items": [{"value": "first.invalid"}, {"value": "one@example.invalid", "type": "email"}]},
            {"items": [{"type": "ip"}, {"value": "second.invalid", "type": "domain"}]},
            {"items": [{"value": "last.invalid"}]},
        ]}
        result = candidates(alert, {
            "value_path": "groups[*].items[*].value", "type_path": "groups[*].items[*].type",
        })
        self.assertEqual(result, [("first.invalid", None), ("one@example.invalid", "excluded"),
                                  ("second.invalid", "domain"), ("last.invalid", None)])

    def test_adjacent_nested_wildcards_preserve_sparse_array_positions(self):
        alert = {"matrix": [
            [{"value": "first.invalid"}],
            [{"value": "two@example.invalid", "type": "email"}, {"value": "last.invalid", "type": "domain"}],
        ]}
        result = candidates(alert, {"value_path": "matrix[*][*].value", "type_path": "matrix[*][*].type"})
        self.assertEqual(result, [("first.invalid", None), ("two@example.invalid", "excluded"),
                                  ("last.invalid", "domain")])

    def test_fixed_type_is_fallback_for_a_missing_or_unknown_sibling_type(self):
        alert = {"observables": [
            {"value": "9.9.9.9"}, {"value": "8.8.8.8", "type": "vendor-unknown"},
            {"value": "example.invalid", "type": "domain"},
        ]}
        result = candidates(alert, {
            "value_path": "observables[*].value", "type_path": "observables[*].type", "type": "ip",
        })
        self.assertEqual(result, [("9.9.9.9", "ip"), ("8.8.8.8", "ip"), ("example.invalid", "domain")])
        self.assertEqual(candidates({"target": "example.invalid"}, {"value_path": "target", "type": "domain"}),
                         [("example.invalid", "domain")])

    def test_scalar_type_path_broadcasts_to_all_values(self):
        alert = {"kind": "domain", "observables": [{"value": "first.invalid"}, {"value": "last.invalid"}]}
        result = candidates(alert, {"value_path": "observables[*].value", "type_path": "kind"})
        self.assertEqual(result, [("first.invalid", "domain"), ("last.invalid", "domain")])

    def test_dollar_prefix_and_root_preserve_existing_path_support(self):
        alert = {"data": {"kind": "domain", "observables": [{"value": "example.invalid"}]}}
        result = candidates(alert, {"value_path": "$.data.observables[*].value", "type_path": "$.data.kind"})
        self.assertEqual(result, [("example.invalid", "domain")])
        self.assertEqual(_json_path_values(alert, "$"), [alert])
        self.assertEqual(_json_path_values(alert, "$.data.observables[*].value"), ["example.invalid"])

    def test_malformed_paths_raise_even_when_the_alert_has_no_matching_data(self):
        for path in ("", " ", "$.", ".value", "data..value", "data.", "data[0].value",
                     "data[**].value", "data[*]trailing", "data[?(@.type)]", "data. type", "$data"):
            with self.subTest(path=path, part="value"), self.assertRaises(ValueError):
                candidates({}, {"value_path": path})
            with self.subTest(path=path, part="type"), self.assertRaises(ValueError):
                candidates({}, {"value_path": "data.value", "type_path": path})
        for value in (None, 1, ["data.type"]):
            with self.subTest(type_path=value), self.assertRaises(ValueError):
                candidates({}, {"value_path": "data.value", "type_path": value})

    def test_wildcard_type_path_cannot_broadcast_or_match_another_depth(self):
        for value_path, type_path in (
            ("value", "types[*]"),
            ("groups[*].values[*]", "groups[*].type"),
            ("values[*]", "groups[*].types[*]"),
        ):
            with self.subTest(value_path=value_path, type_path=type_path), self.assertRaises(ValueError):
                candidates({}, {"value_path": value_path, "type_path": type_path})

    def test_wildcards_require_arrays_instead_of_treating_scalars_as_singletons(self):
        with self.assertRaises(ValueError):
            candidates({"observables": {"value": "example.invalid"}}, {"value_path": "observables[*].value"})
        with self.assertRaises(ValueError):
            candidates({"observables": [{"values": ["example.invalid"], "types": "domain"}]}, {
                "value_path": "observables[*].values[*]", "type_path": "observables[*].types[*]",
            })


if __name__ == "__main__":
    unittest.main()
