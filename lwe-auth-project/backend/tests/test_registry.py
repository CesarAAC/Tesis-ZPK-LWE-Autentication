import unittest

from crypto_core.exceptions import ProtocolUnavailableError, UnknownProtocolError
from crypto_core.registry import (
    ProtocolSpec,
    available_protocol_names,
    get_protocol,
    get_protocol_spec,
    protocol_catalog,
)


class ProtocolRegistryTests(unittest.TestCase):
    def test_catalog_contains_exactly_the_six_thesis_candidates(self) -> None:
        self.assertEqual(
            tuple(spec.protocol_id for spec in protocol_catalog()),
            (
                "ecdsa",
                "standard_lwe",
                "binary_lwe",
                "ring_lwe",
                "lwr",
                "proposed_lwe",
            ),
        )

    def test_all_six_candidates_are_complete_and_advertised(self) -> None:
        self.assertEqual(
            available_protocol_names(),
            ("ecdsa", "standard_lwe", "binary_lwe", "ring_lwe", "lwr", "proposed_lwe"),
        )

    def test_legacy_ecdsa_alias_resolves(self) -> None:
        self.assertEqual(get_protocol("standard").name, "standard_ecdsa")
        self.assertEqual(get_protocol("standard_ecdsa").name, "standard_ecdsa")

    def test_lwe_alias_maps_to_standard_lwe_candidate(self) -> None:
        self.assertEqual(get_protocol_spec("lwe").protocol_id, "standard_lwe")

    def test_lattice_candidates_resolve_to_complete_implementations(self) -> None:
        self.assertEqual(get_protocol("lwe").name, "standard_lwe")
        self.assertEqual(get_protocol("binary_lwe").name, "binary_lwe")
        self.assertEqual(get_protocol("ring_lwe").name, "ring_lwe")
        self.assertEqual(get_protocol("lwr").name, "lwr")
        self.assertEqual(get_protocol("lwrounding").name, "lwr")

    def test_proposed_protocol_resolves_by_id_and_alias(self) -> None:
        self.assertEqual(get_protocol("proposed_lwe").name, "proposed_lwe")
        self.assertEqual(get_protocol("custom_lwe").name, "proposed_lwe")
        self.assertIn("cryptography", get_protocol_spec("proposed_lwe").declared_dependencies)

    def test_catalog_entry_without_implementation_fails_closed(self) -> None:
        pending = ProtocolSpec(
            protocol_id="pending",
            display_name="Pending",
            family="none",
            aliases=(),
            declared_dependencies=(),
            implementation_factory=None,
            development_note="Sin implementar.",
        )
        self.assertFalse(pending.available)
        with self.assertRaises(ProtocolUnavailableError):
            pending.require_implementation()

    def test_unknown_protocol_is_rejected(self) -> None:
        with self.assertRaises(UnknownProtocolError):
            get_protocol("does_not_exist")


if __name__ == "__main__":
    unittest.main()
