import unittest

from crypto_core.exceptions import ProtocolUnavailableError, UnknownProtocolError
from crypto_core.registry import available_protocol_names, get_protocol


class ProtocolRegistryTests(unittest.TestCase):
    def test_only_complete_protocols_are_advertised(self) -> None:
        self.assertEqual(available_protocol_names(), ("standard",))

    def test_ecdsa_alias_resolves_to_standard_protocol(self) -> None:
        self.assertEqual(get_protocol("standard_ecdsa").name, "standard_ecdsa")

    def test_incomplete_lwe_protocol_fails_closed(self) -> None:
        with self.assertRaises(ProtocolUnavailableError):
            get_protocol("lwe")

    def test_unknown_protocol_is_rejected(self) -> None:
        with self.assertRaises(UnknownProtocolError):
            get_protocol("does_not_exist")


if __name__ == "__main__":
    unittest.main()
