import base64
import unittest

from crypto_core.exceptions import InvalidProtocolDataError
from crypto_core.protocols.ecdsa import StandardECDSAProtocol


class StandardECDSAProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.protocol = StandardECDSAProtocol()
        self.public_key, self.private_key = self.protocol.generate_keypair()

    def test_round_trip_is_valid(self) -> None:
        challenge = self.protocol.generate_challenge(self.public_key)
        response = self.protocol.solve_challenge(self.private_key, challenge)

        self.assertTrue(
            self.protocol.verify_response(self.public_key, challenge, response)
        )

    def test_modified_challenge_is_rejected(self) -> None:
        challenge = self.protocol.generate_challenge(self.public_key)
        response = self.protocol.solve_challenge(self.private_key, challenge)

        tampered_nonce = bytearray(base64.b64decode(challenge["nonce"]))
        tampered_nonce[0] ^= 1
        tampered_challenge = {
            "nonce": base64.b64encode(bytes(tampered_nonce)).decode("ascii")
        }

        self.assertFalse(
            self.protocol.verify_response(
                self.public_key,
                tampered_challenge,
                response,
            )
        )

    def test_malformed_private_key_is_rejected(self) -> None:
        challenge = self.protocol.generate_challenge(self.public_key)

        with self.assertRaises(InvalidProtocolDataError):
            self.protocol.solve_challenge({"key_pem": "not-base64!"}, challenge)


if __name__ == "__main__":
    unittest.main()
