import copy
import unittest

import numpy as np

from crypto_core.exceptions import InvalidProtocolDataError
from crypto_core.lwe import codec, lwr, regev
from crypto_core.protocols.lwr_auth import LWRProtocol


class LWRPrimitiveTests(unittest.TestCase):
    def test_round_q_to_p_maps_modulus_endpoint_back_to_zero(self) -> None:
        values = np.array([0, 1, 2048, 4095], dtype=np.int64)
        rounded = lwr.round_q_to_p(values, 4096, 1024)
        self.assertEqual(int(rounded[0]), 0)
        self.assertGreaterEqual(int(rounded.min()), 0)
        self.assertLess(int(rounded.max()), 1024)


class LWRProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.protocol = LWRProtocol()
        self.parameters = self.protocol.resolve_parameters(
            {"n": 64, "q": 4096, "p": 1024, "message_bits": 128}
        )
        self.system_parameters = self.protocol.generate_system_parameters(**self.parameters)
        self.public_key, self.private_key = self.protocol.generate_keypair(
            self.system_parameters, **self.parameters
        )

    def test_effective_parameters_include_derived_m(self) -> None:
        expected_m = regev.leftover_hash_min_samples(64, 4096, 256)
        self.assertEqual(self.parameters["m"], expected_m)
        self.assertEqual(self.system_parameters["parameters"], self.parameters)
        self.assertEqual(
            self.parameters["noise_mechanism"],
            "deterministic_modulus_rounding",
        )

    def test_round_trip_is_valid(self) -> None:
        challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        response = self.protocol.solve_challenge(
            self.system_parameters, self.private_key, challenge
        )
        self.assertTrue(
            self.protocol.verify_response(
                self.system_parameters, self.public_key, challenge, response
            )
        )

    def test_challenge_modified_is_rejected_by_prover(self) -> None:
        challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        tampered = copy.deepcopy(challenge)
        v = codec.decode_coefficients(
            tampered["v"], "v", (self.parameters["message_bits"],), self.parameters["p"]
        )
        v[0] = (v[0] + 1) % self.parameters["p"]
        tampered["v"] = codec.encode_coefficients(v)
        with self.assertRaises(InvalidProtocolDataError):
            self.protocol.solve_challenge(
                self.system_parameters, self.private_key, tampered
            )

    def test_response_is_bound_to_public_key(self) -> None:
        challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        response = self.protocol.solve_challenge(
            self.system_parameters, self.private_key, challenge
        )
        other_public, _ = self.protocol.generate_keypair(
            self.system_parameters, **self.parameters
        )
        self.assertFalse(
            self.protocol.verify_response(
                self.system_parameters, other_public, challenge, response
            )
        )

    def test_rounding_moduli_must_be_nested_powers_of_two(self) -> None:
        with self.assertRaises(InvalidProtocolDataError):
            self.protocol.resolve_parameters({"n": 64, "q": 4096, "p": 3000})
        with self.assertRaises(InvalidProtocolDataError):
            self.protocol.resolve_parameters({"n": 64, "q": 4096, "p": 4096})

    def test_too_few_samples_are_rejected(self) -> None:
        with self.assertRaises(InvalidProtocolDataError):
            self.protocol.resolve_parameters(
                {"n": 64, "q": 4096, "p": 1024, "m": 128}
            )

    def test_public_key_is_rounded_mod_p(self) -> None:
        vector_b = codec.decode_coefficients(
            self.public_key["b"], "b", (self.parameters["m"],), self.parameters["p"]
        )
        self.assertGreaterEqual(int(vector_b.min()), 0)
        self.assertLess(int(vector_b.max()), self.parameters["p"])


if __name__ == "__main__":
    unittest.main()
