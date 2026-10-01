import base64
import math
import unittest

import numpy as np

from crypto_core.exceptions import InvalidProtocolDataError
from crypto_core.lwe import codec, sampling
from crypto_core.protocols.lattice_zk import challenge_space_bits
from crypto_core.protocols.lwe_zk import BinaryLWEProtocol, StandardLWEProtocol
from tests.lattice_zk_cases import LatticeZKProtocolCases

SMALL_PARAMETERS = {"n": 128, "m": 128}


class _MatrixLWECases(LatticeZKProtocolCases):
    small_parameters = SMALL_PARAMETERS
    alternative_parameters = {**SMALL_PARAMETERS, "m": 160}
    shared_field = "matrix_a"
    public_field = "B"
    witness_fields = ("S", "E")
    invalid_overrides = (
        {"n": 8},
        {"m": 1 << 13},
        {"ell": 8},
        {"eta": 0},
        {"eta": 9},
        {"p": 1024},
        {"secret_distribution": "uniform_mod_q"},
    )

    def _decoded_key(self):
        parameters = self.parameters
        matrix_a = codec.decode_unsigned(
            self.system_parameters["matrix_a"],
            "matrix_a",
            (parameters["m"], parameters["n"]),
            parameters["q"],
        )[1]
        public = codec.decode_unsigned(
            self.public_key["B"],
            "B",
            (parameters["m"], parameters["ell"]),
            parameters["q"],
        )[1]
        error = codec.decode_signed(
            self.private_key["E"],
            "E",
            (parameters["m"], parameters["ell"]),
            parameters["eta"],
        )
        return matrix_a, public, error

    def test_key_satisfies_the_lwe_relation(self) -> None:
        matrix_a, public, error = self._decoded_key()
        secret = self.protocol._decode_secret(self.private_key["S"], self.parameters)
        self.assertTrue(
            np.array_equal((matrix_a @ secret + error) % self.parameters["q"], public)
        )

    def test_default_challenge_space_is_at_least_128_bits(self) -> None:
        defaults = self.protocol.resolve_parameters()
        self.assertGreaterEqual(challenge_space_bits(defaults["ell"], defaults["kappa"]), 128)


class StandardLWEProtocolTests(_MatrixLWECases, unittest.TestCase):
    protocol_class = StandardLWEProtocol
    expected_defaults = {
        "n": 1024,
        "m": 1024,
        "q": 8380417,
        "eta": 2,
        "ell": 128,
        "kappa": 31,
        "gamma": 1 << 17,
        "secret_distribution": "centered_binomial",
    }

    def test_secret_is_centered_binomial(self) -> None:
        secret = self.protocol._decode_secret(self.private_key["S"], self.parameters)
        self.assertLessEqual(int(np.abs(secret).max()), self.parameters["eta"])
        self.assertLess(int(secret.min()), 0)


class BinaryLWEProtocolTests(_MatrixLWECases, unittest.TestCase):
    protocol_class = BinaryLWEProtocol
    expected_defaults = {
        "n": 1024,
        "m": 1024,
        "q": 8380417,
        "eta": 2,
        "ell": 128,
        "kappa": 31,
        "secret_distribution": "binary",
    }

    def test_secret_is_binary_and_bit_packed(self) -> None:
        secret = self.protocol._decode_secret(self.private_key["S"], self.parameters)
        self.assertTrue(set(np.unique(secret).tolist()) <= {0, 1})
        self.assertEqual(
            len(base64.b64decode(self.private_key["S"])),
            math.ceil(self.parameters["n"] * self.parameters["ell"] / 8),
        )


class LatticeSamplingTests(unittest.TestCase):
    def test_sparse_ternary_challenge_has_exact_weight_and_is_deterministic(self) -> None:
        first = sampling.derive_sparse_ternary(b"seed", 128, 31)
        second = sampling.derive_sparse_ternary(b"seed", 128, 31)
        other = sampling.derive_sparse_ternary(b"other", 128, 31)
        self.assertTrue(np.array_equal(first, second))
        self.assertFalse(np.array_equal(first, other))
        self.assertEqual(int(np.count_nonzero(first)), 31)
        self.assertTrue(set(np.unique(first).tolist()) <= {-1, 0, 1})

    def test_sparse_ternary_positions_cover_the_whole_vector(self) -> None:
        hits = np.zeros(64, dtype=np.int64)
        for index in range(400):
            hits += np.abs(sampling.derive_sparse_ternary(index.to_bytes(4, "little"), 64, 8))
        self.assertTrue(np.all(hits > 0))

    def test_uniform_box_respects_bounds(self) -> None:
        values = sampling.sample_uniform_box((50000,), 7)
        self.assertEqual((int(values.min()), int(values.max())), (-7, 7))

    def test_signed_codec_uses_minimal_width_and_rejects_out_of_range(self) -> None:
        encoded = codec.encode_signed(np.array([-2, 0, 2]), 2)
        self.assertEqual(len(base64.b64decode(encoded)), 3)
        self.assertEqual(codec.decode_signed(encoded, "x", (3,), 2).tolist(), [-2, 0, 2])
        with self.assertRaises(InvalidProtocolDataError):
            codec.decode_signed(encoded, "x", (3,), 1)

    def test_challenge_space_bits_matches_exact_count(self) -> None:
        # C(4, 2) * 2^2 = 24 vectors.
        self.assertAlmostEqual(challenge_space_bits(4, 2), math.log2(24))


if __name__ == "__main__":
    unittest.main()
