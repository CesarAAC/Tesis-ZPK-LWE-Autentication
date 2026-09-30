import copy
import unittest

import numpy as np

from crypto_core.exceptions import InvalidProtocolDataError
from crypto_core.lwe import codec, ring, sampling
from crypto_core.protocols.ring_lwe import RingLWEProtocol


class RingLWEPrimitiveTests(unittest.TestCase):
    def test_negacyclic_multiplication_reduces_x_n_to_minus_one(self) -> None:
        left = np.zeros(8, dtype=np.int64)
        right = np.zeros(8, dtype=np.int64)
        left[-1] = 1
        right[1] = 1
        product = ring.negacyclic_multiply(left, right, 17)
        expected = np.zeros(8, dtype=np.int64)
        expected[0] = 16
        self.assertTrue(np.array_equal(product, expected))

    def test_derived_centered_binomial_is_deterministic_and_bounded(self) -> None:
        first = sampling.derive_centered_binomial(b"seed", (512,), 2)
        second = sampling.derive_centered_binomial(b"seed", (512,), 2)
        other = sampling.derive_centered_binomial(b"other", (512,), 2)
        self.assertTrue(np.array_equal(first, second))
        self.assertFalse(np.array_equal(first, other))
        self.assertGreaterEqual(int(first.min()), -2)
        self.assertLessEqual(int(first.max()), 2)


class RingLWEProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.protocol = RingLWEProtocol()
        self.parameters = self.protocol.resolve_parameters(
            {"n": 128, "q": 12289, "eta": 2, "message_bits": 128}
        )
        self.system_parameters = self.protocol.generate_system_parameters(**self.parameters)
        self.public_key, self.private_key = self.protocol.generate_keypair(
            self.system_parameters, **self.parameters
        )

    def test_effective_parameters_are_explicit(self) -> None:
        self.assertEqual(self.system_parameters["parameters"], self.parameters)
        self.assertEqual(self.parameters["ring"], "Z_q[x]/(x^n+1)")
        self.assertEqual(self.parameters["secret_distribution"], "centered_binomial")

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
        u = codec.decode_coefficients(
            tampered["u"], "u", (self.parameters["n"],), self.parameters["q"]
        )
        u[0] = (u[0] + 1) % self.parameters["q"]
        tampered["u"] = codec.encode_coefficients(u)
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

    def test_invalid_ring_dimension_is_rejected(self) -> None:
        with self.assertRaises(InvalidProtocolDataError):
            self.protocol.resolve_parameters(
                {"n": 192, "q": 12289, "eta": 2, "message_bits": 128}
            )

    def test_message_must_fit_in_ring(self) -> None:
        with self.assertRaises(InvalidProtocolDataError):
            self.protocol.resolve_parameters(
                {"n": 128, "q": 12289, "eta": 2, "message_bits": 256}
            )

    def test_malformed_small_secret_is_rejected(self) -> None:
        malformed = copy.deepcopy(self.private_key)
        secret = codec.decode_coefficients(
            malformed["s"], "s", (self.parameters["n"],), self.parameters["q"]
        )
        secret[0] = 10
        malformed["s"] = codec.encode_coefficients(secret)
        challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        with self.assertRaises(InvalidProtocolDataError):
            self.protocol.solve_challenge(
                self.system_parameters, malformed, challenge
            )


if __name__ == "__main__":
    unittest.main()
