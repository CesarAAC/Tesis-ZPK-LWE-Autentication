import base64
import unittest

from crypto_core.exceptions import InvalidProtocolDataError
from crypto_core.protocols.ecdsa import StandardECDSAProtocol


class StandardECDSAProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.protocol = StandardECDSAProtocol()
        self.parameters = self.protocol.resolve_parameters()
        self.system_parameters = self.protocol.generate_system_parameters(**self.parameters)
        self.public_key, self.private_key = self.protocol.generate_keypair(
            self.system_parameters,
            **self.parameters,
        )

    def test_round_trip_is_valid(self) -> None:
        challenge = self.protocol.generate_challenge(
            self.system_parameters,
            self.public_key,
        )
        response = self.protocol.solve_challenge(
            self.system_parameters,
            self.private_key,
            challenge,
        )

        self.assertTrue(
            self.protocol.verify_response(
                self.system_parameters,
                self.public_key,
                challenge,
                response,
            )
        )

    def test_modified_challenge_is_rejected(self) -> None:
        challenge = self.protocol.generate_challenge(
            self.system_parameters,
            self.public_key,
        )
        response = self.protocol.solve_challenge(
            self.system_parameters,
            self.private_key,
            challenge,
        )

        tampered_nonce = bytearray(base64.b64decode(challenge["nonce"]))
        tampered_nonce[0] ^= 1
        tampered_challenge = {
            "nonce": base64.b64encode(bytes(tampered_nonce)).decode("ascii")
        }

        self.assertFalse(
            self.protocol.verify_response(
                self.system_parameters,
                self.public_key,
                tampered_challenge,
                response,
            )
        )

    def test_malformed_private_key_is_rejected(self) -> None:
        challenge = self.protocol.generate_challenge(
            self.system_parameters,
            self.public_key,
        )

        with self.assertRaises(InvalidProtocolDataError):
            self.protocol.solve_challenge(
                self.system_parameters,
                {"key_pem": "not-base64!"},
                challenge,
            )

    def test_effective_parameters_are_explicit(self) -> None:
        self.assertEqual(
            self.protocol.resolve_parameters(),
            {
                "curve": "secp256r1",
                "hash": "sha256",
                "challenge_bytes": 32,
            },
        )

    def test_ecdsa_has_no_generated_shared_setup_material(self) -> None:
        self.assertEqual(self.system_parameters, {})

    def test_unsupported_parameter_override_is_rejected(self) -> None:
        with self.assertRaises(InvalidProtocolDataError):
            self.protocol.resolve_parameters({"curve": "secp384r1"})


if __name__ == "__main__":
    unittest.main()
