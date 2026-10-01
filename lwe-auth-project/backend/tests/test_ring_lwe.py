import unittest

import numpy as np

from crypto_core.lwe import codec, ring
from crypto_core.protocols.ring_lwe import RingLWEProtocol
from tests.lattice_zk_cases import LatticeZKProtocolCases

SMALL_PARAMETERS = {"n": 256, "kappa": 23}


class RingLWEProtocolTests(LatticeZKProtocolCases, unittest.TestCase):
    protocol_class = RingLWEProtocol
    small_parameters = SMALL_PARAMETERS
    alternative_parameters = {**SMALL_PARAMETERS, "kappa": 24}
    shared_field = "a"
    public_field = "b"
    witness_fields = ("s", "e")
    expected_defaults = {
        "n": 1024,
        "q": 8380417,
        "eta": 2,
        "kappa": 16,
        "gamma": 1 << 17,
        "ring": "Z_q[x]/(x^n+1)",
    }
    invalid_overrides = (
        {"n": 384},
        {"n": 32},
        {"n": 8192},
        {"eta": 0},
        {"m": 1024},
        {"polynomial_multiplication": "ntt"},
    )

    def test_key_satisfies_the_ring_lwe_relation(self) -> None:
        n, q, eta = self.parameters["n"], self.parameters["q"], self.parameters["eta"]
        polynomial_a = codec.decode_unsigned(self.system_parameters["a"], "a", (n,), q)[1]
        public = codec.decode_unsigned(self.public_key["b"], "b", (n,), q)[1]
        secret = codec.decode_signed(self.private_key["s"], "s", (n,), eta)
        error = codec.decode_signed(self.private_key["e"], "e", (n,), eta)
        self.assertTrue(
            np.array_equal((ring.negacyclic_multiply(polynomial_a, secret, q) + error) % q, public)
        )

    def test_challenge_is_a_single_ring_element(self) -> None:
        context = self.protocol._context(self.system_parameters)
        self.assertEqual(self.protocol._challenge_shape(context), (256, 23))


class NegacyclicMultiplicationTests(unittest.TestCase):
    def test_matches_reference_reduction_modulo_x_n_plus_1(self) -> None:
        rng = np.random.default_rng(1)
        n, q = 16, 97
        left = rng.integers(0, q, n)
        right = rng.integers(-3, 4, n)
        expected = np.zeros(n, dtype=np.int64)
        for i in range(n):
            for j in range(n):
                sign = 1 if i + j < n else -1
                expected[(i + j) % n] += sign * left[i] * right[j]
        self.assertTrue(np.array_equal(ring.negacyclic_multiply(left, right, q), expected % q))

    def test_x_to_the_n_equals_minus_one(self) -> None:
        left = np.zeros(8, dtype=np.int64)
        right = np.zeros(8, dtype=np.int64)
        left[-1] = 1
        right[1] = 1
        expected = np.zeros(8, dtype=np.int64)
        expected[0] = 16
        self.assertTrue(np.array_equal(ring.negacyclic_multiply(left, right, 17), expected))


if __name__ == "__main__":
    unittest.main()
