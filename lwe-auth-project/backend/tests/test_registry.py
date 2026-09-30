import unittest

from crypto_core.exceptions import ProtocolUnavailableError, UnknownProtocolError
from crypto_core.registry import (
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

    def test_only_complete_protocols_are_advertised(self) -> None:
        self.assertEqual(available_protocol_names(), ("ecdsa",))

    def test_legacy_ecdsa_alias_resolves(self) -> None:
        self.assertEqual(get_protocol("standard").name, "standard_ecdsa")
        self.assertEqual(get_protocol("standard_ecdsa").name, "standard_ecdsa")

    def test_lwe_alias_maps_to_standard_lwe_candidate(self) -> None:
        self.assertEqual(get_protocol_spec("lwe").protocol_id, "standard_lwe")

    def test_incomplete_lwe_protocol_fails_closed(self) -> None:
        with self.assertRaises(ProtocolUnavailableError):
            get_protocol("standard_lwe")

    def test_unknown_protocol_is_rejected(self) -> None:
        with self.assertRaises(UnknownProtocolError):
            get_protocol("does_not_exist")


if __name__ == "__main__":
    unittest.main()
