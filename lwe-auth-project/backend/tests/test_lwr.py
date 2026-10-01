import unittest

import numpy as np

from crypto_core.lwe import codec, lwr
from crypto_core.protocols.lwr_auth import LWRProtocol
from tests.lattice_zk_cases import LatticeZKProtocolCases

SMALL_PARAMETERS = {"n": 128, "m": 128}


class LWRProtocolTests(LatticeZKProtocolCases, unittest.TestCase):
    protocol_class = LWRProtocol
    small_parameters = SMALL_PARAMETERS
    alternative_parameters = {**SMALL_PARAMETERS, "p": 1 << 19}
    shared_field = "matrix_a"
    public_field = "B"
    witness_fields = ("S", "E")
    expected_defaults = {
        "n": 1024,
        "m": 1024,
        "q": 1 << 23,
        "p": 1 << 20,
        "eta": 2,
        "ell": 128,
        "kappa": 31,
        "noise_mechanism": "deterministic_modulus_rounding",
    }
    invalid_overrides = (
        {"q": 8380417},
        {"p": 1000},
        {"p": 1 << 23},
        {"p": 2},
        {"p": 1 << 15},
        {"sigma": 2.8},
        {"rounding": "floor"},
    )

    def _decoded(self):
        parameters = self.parameters
        q, p = parameters["q"], parameters["p"]
        shape = (parameters["m"], parameters["ell"])
        matrix_a = codec.decode_unsigned(
            self.system_parameters["matrix_a"],
            "matrix_a",
            (parameters["m"], parameters["n"]),
            q,
        )[1]
        public = codec.decode_unsigned(self.public_key["B"], "B", shape, p)[1]
        secret = self.protocol._decode_secret(self.private_key["S"], parameters)
        error = codec.decode_signed(self.private_key["E"], "E", shape, q // (2 * p))
        return matrix_a, public, secret, error

    def test_public_key_is_the_rounding_of_a_s(self) -> None:
        matrix_a, public, secret, _ = self._decoded()
        q, p = self.parameters["q"], self.parameters["p"]
        self.assertTrue(np.array_equal(lwr.round_q_to_p(matrix_a @ secret, q, p), public))

    def test_rounding_error_satisfies_lifted_relation(self) -> None:
        matrix_a, public, secret, error = self._decoded()
        q, p = self.parameters["q"], self.parameters["p"]
        self.assertTrue(
            np.array_equal((matrix_a @ secret + error) % q, ((q // p) * public) % q)
        )
        self.assertLessEqual(int(np.abs(error).max()), q // (2 * p))


class RoundingTests(unittest.TestCase):
    def test_round_q_to_p_is_nearest_integer_mod_p(self) -> None:
        values = np.array([0, 3, 4, 5, 12, 15], dtype=np.int64)
        # q = 16, p = 2: x * 2 / 16 rounded to nearest, ties (x = 4, 12) round up.
        self.assertEqual(lwr.round_q_to_p(values, 16, 2).tolist(), [0, 0, 1, 1, 0, 0])


if __name__ == "__main__":
    unittest.main()
