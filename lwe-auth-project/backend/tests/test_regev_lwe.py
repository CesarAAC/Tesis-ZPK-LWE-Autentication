import base64
import copy
import math
import unittest

import numpy as np

from benchmarking.serialization import canonical_json_bytes
from crypto_core.exceptions import InvalidProtocolDataError
from crypto_core.lwe import codec, regev, sampling
from crypto_core.protocols.regev_lwe import BinaryLWEProtocol, StandardLWEProtocol

# Small but valid parameters keep the suite fast; defaults are covered separately.
SMALL_PARAMETERS = {"n": 64, "q": 4096, "sigma": 2.8, "message_bits": 128}


def _flip_first_byte(encoded: str) -> str:
    raw = bytearray(base64.b64decode(encoded))
    raw[0] ^= 1
    return base64.b64encode(bytes(raw)).decode("ascii")


class _RegevLWEProtocolTests:
    protocol_class: type

    def setUp(self) -> None:
        self.protocol = self.protocol_class()
        self.parameters = self.protocol.resolve_parameters(SMALL_PARAMETERS)
        self.system_parameters = self.protocol.generate_system_parameters(**self.parameters)
        self.public_key, self.private_key = self.protocol.generate_keypair(
            self.system_parameters,
            **self.parameters,
        )

    def _challenge_and_response(self):
        challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        response = self.protocol.solve_challenge(
            self.system_parameters,
            self.private_key,
            challenge,
        )
        return challenge, response

    def _verify(self, challenge, response, public_key=None) -> bool:
        return self.protocol.verify_response(
            self.system_parameters,
            public_key or self.public_key,
            challenge,
            response,
        )

    # -- round trip -------------------------------------------------------------

    def test_round_trip_is_valid(self) -> None:
        for _ in range(5):
            challenge, response = self._challenge_and_response()
            self.assertTrue(self._verify(challenge, response))

    def test_round_trip_with_default_parameters(self) -> None:
        parameters = self.protocol.resolve_parameters()
        system_parameters = self.protocol.generate_system_parameters(**parameters)
        public_key, private_key = self.protocol.generate_keypair(
            system_parameters,
            **parameters,
        )
        challenge = self.protocol.generate_challenge(system_parameters, public_key)
        response = self.protocol.solve_challenge(system_parameters, private_key, challenge)
        self.assertTrue(
            self.protocol.verify_response(system_parameters, public_key, challenge, response)
        )

    # -- challenge binding --------------------------------------------------------

    def test_challenges_are_fresh(self) -> None:
        first = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        second = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        self.assertNotEqual(first["nonce"], second["nonce"])
        self.assertNotEqual(first["commitment"], second["commitment"])

    def test_response_is_rejected_under_another_challenge(self) -> None:
        _, response = self._challenge_and_response()
        other_challenge = self.protocol.generate_challenge(
            self.system_parameters,
            self.public_key,
        )
        self.assertFalse(self._verify(other_challenge, response))

    def test_modified_challenge_is_rejected(self) -> None:
        challenge, response = self._challenge_and_response()
        for field in ("nonce", "u", "v", "commitment"):
            with self.subTest(field=field):
                tampered = dict(challenge, **{field: _flip_first_byte(challenge[field])})
                self.assertFalse(self._verify(tampered, response))

    def test_modified_response_is_rejected(self) -> None:
        challenge, response = self._challenge_and_response()
        tampered = {"message": _flip_first_byte(response["message"])}
        self.assertFalse(self._verify(challenge, tampered))

    def test_prover_refuses_ciphertext_not_matching_reencryption(self) -> None:
        challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        tampered = dict(challenge, u=_flip_first_byte(challenge["u"]))
        with self.assertRaises(InvalidProtocolDataError):
            self.protocol.solve_challenge(self.system_parameters, self.private_key, tampered)

    # -- public key binding -------------------------------------------------------

    def test_response_is_rejected_under_another_public_key(self) -> None:
        challenge, response = self._challenge_and_response()
        other_public, _ = self.protocol.generate_keypair(
            self.system_parameters,
            **self.parameters,
        )
        self.assertFalse(self._verify(challenge, response, other_public))

    def test_other_private_key_cannot_answer_challenge(self) -> None:
        challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        _, other_private = self.protocol.generate_keypair(
            self.system_parameters,
            **self.parameters,
        )
        with self.assertRaises(InvalidProtocolDataError):
            self.protocol.solve_challenge(self.system_parameters, other_private, challenge)

    # -- malformed inputs -----------------------------------------------------------

    def test_malformed_private_key_is_rejected(self) -> None:
        challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        for private_key in (
            {"s": "not-base64!", "b": self.private_key["b"]},
            {"b": self.private_key["b"]},
            {"s": self.private_key["s"], "b": "AAAA"},
            "not-a-mapping",
        ):
            with self.subTest(private_key=str(private_key)[:40]):
                with self.assertRaises(InvalidProtocolDataError):
                    self.protocol.solve_challenge(
                        self.system_parameters,
                        private_key,
                        challenge,
                    )

    def test_public_key_with_coefficient_outside_zq_is_rejected(self) -> None:
        raw = bytearray(base64.b64decode(self.public_key["b"]))
        raw[0:2] = (self.parameters["q"]).to_bytes(2, "little")
        public_key = {"b": base64.b64encode(bytes(raw)).decode("ascii")}
        with self.assertRaises(InvalidProtocolDataError):
            self.protocol.generate_challenge(self.system_parameters, public_key)

    def test_malformed_challenge_and_response_are_rejected(self) -> None:
        challenge, response = self._challenge_and_response()
        with self.assertRaises(InvalidProtocolDataError):
            self._verify({k: v for k, v in challenge.items() if k != "u"}, response)
        with self.assertRaises(InvalidProtocolDataError):
            self._verify(challenge, {"message": response["message"] + "A"})
        with self.assertRaises(InvalidProtocolDataError):
            self._verify(challenge, {"message": base64.b64encode(b"short").decode("ascii")})

    # -- parameters -----------------------------------------------------------------

    def test_effective_parameters_are_explicit(self) -> None:
        resolved = self.protocol.resolve_parameters()
        self.assertEqual(resolved, self.protocol.default_parameters())
        self.assertEqual((resolved["n"], resolved["q"], resolved["sigma"]), (640, 32768, 2.8))
        self.assertEqual(resolved["m"], regev.leftover_hash_min_samples(640, 32768, 256))
        self.assertEqual(resolved["secret_distribution"], self.expected_secret_distribution)

    def test_m_is_derived_from_n_and_q_when_not_overridden(self) -> None:
        self.assertEqual(self.parameters["m"], (64 + 1) * 12 + 256)

    def test_invalid_parameters_are_rejected(self) -> None:
        invalid_overrides = (
            {"unknown": 1},
            {"n": True},
            {"n": 0},
            {"q": 1},
            {"q": 1 << 17},
            {"sigma": 0},
            {"sigma": "3"},
            {"message_bits": 120},
            {"message_bits": 130},
            {**SMALL_PARAMETERS, "m": 512},
            {**SMALL_PARAMETERS, "q": 1024},
            {"secret_distribution": "gaussian"},
            {"hash": "sha256"},
        )
        for overrides in invalid_overrides:
            with self.subTest(overrides=overrides):
                with self.assertRaises(InvalidProtocolDataError):
                    self.protocol.resolve_parameters(overrides)

    def test_larger_m_override_is_accepted(self) -> None:
        resolved = self.protocol.resolve_parameters({**SMALL_PARAMETERS, "m": 1100})
        self.assertEqual(resolved["m"], 1100)

    # -- setup / serialization / mutation -------------------------------------------

    def test_system_parameters_carry_shared_matrix_and_effective_parameters(self) -> None:
        self.assertEqual(self.system_parameters["protocol"], self.protocol.name)
        self.assertEqual(self.system_parameters["parameters"], self.parameters)
        matrix = codec.decode_coefficients(
            self.system_parameters["matrix_a"],
            "matrix_a",
            (self.parameters["m"], self.parameters["n"]),
            self.parameters["q"],
        )
        self.assertEqual(matrix.shape, (self.parameters["m"], self.parameters["n"]))

    def test_setup_generates_a_fresh_matrix(self) -> None:
        other = self.protocol.generate_system_parameters(**self.parameters)
        self.assertNotEqual(other["matrix_a"], self.system_parameters["matrix_a"])

    def test_keygen_rejects_parameters_different_from_setup(self) -> None:
        with self.assertRaises(InvalidProtocolDataError):
            self.protocol.generate_keypair(
                self.system_parameters,
                **{**SMALL_PARAMETERS, "m": 1100},
            )

    def test_system_parameters_of_another_protocol_are_rejected(self) -> None:
        foreign = dict(self.system_parameters, protocol="ecdsa")
        with self.assertRaises(InvalidProtocolDataError):
            self.protocol.generate_challenge(foreign, self.public_key)

    def test_non_canonical_system_parameters_are_rejected(self) -> None:
        parameters = dict(self.parameters)
        del parameters["transform"]
        altered = dict(self.system_parameters, parameters=parameters)
        with self.assertRaises(InvalidProtocolDataError):
            self.protocol.generate_challenge(altered, self.public_key)

    def test_all_artifacts_are_json_serializable(self) -> None:
        challenge, response = self._challenge_and_response()
        for artifact in (
            self.system_parameters,
            self.public_key,
            self.private_key,
            challenge,
            response,
        ):
            canonical_json_bytes(artifact)

    def test_operations_do_not_mutate_inputs(self) -> None:
        originals = copy.deepcopy((self.system_parameters, self.public_key, self.private_key))
        challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        original_challenge = copy.deepcopy(challenge)
        response = self.protocol.solve_challenge(
            self.system_parameters,
            self.private_key,
            challenge,
        )
        original_response = copy.deepcopy(response)
        self._verify(challenge, response)
        self.assertEqual(
            (self.system_parameters, self.public_key, self.private_key),
            originals,
        )
        self.assertEqual(challenge, original_challenge)
        self.assertEqual(response, original_response)

    def test_public_key_is_consistent_with_private_key(self) -> None:
        self.assertEqual(self.public_key["b"], self.private_key["b"])


class StandardLWEProtocolTests(_RegevLWEProtocolTests, unittest.TestCase):
    protocol_class = StandardLWEProtocol
    expected_secret_distribution = "uniform_mod_q"

    def test_secret_is_uniform_in_zq(self) -> None:
        secret = codec.decode_coefficients(
            self.private_key["s"],
            "s",
            (self.parameters["n"],),
            self.parameters["q"],
        )
        self.assertGreater(int(secret.max()), 1)


class BinaryLWEProtocolTests(_RegevLWEProtocolTests, unittest.TestCase):
    protocol_class = BinaryLWEProtocol
    expected_secret_distribution = "binary"

    def test_secret_is_binary_and_bit_packed(self) -> None:
        secret = codec.decode_bits(self.private_key["s"], "s", self.parameters["n"])
        self.assertTrue(set(secret.tolist()) <= {0, 1})
        self.assertEqual(
            len(base64.b64decode(self.private_key["s"])),
            math.ceil(self.parameters["n"] / 8),
        )


class LWESamplingTests(unittest.TestCase):
    def test_uniform_sampler_respects_non_power_of_two_modulus(self) -> None:
        values = sampling.sample_uniform_mod_q((20000,), 3329)
        self.assertEqual(values.shape, (20000,))
        self.assertGreaterEqual(int(values.min()), 0)
        self.assertLess(int(values.max()), 3329)
        self.assertGreater(int(values.max()), 3000)

    def test_discrete_gaussian_has_expected_moments_and_tail_cut(self) -> None:
        values = sampling.sample_discrete_gaussian((200000,), 2.8, 12)
        self.assertLess(abs(float(values.mean())), 0.05)
        self.assertAlmostEqual(float(values.std()), 2.8, delta=0.05)
        self.assertLessEqual(int(np.abs(values).max()), math.ceil(12 * 2.8))

    def test_derived_binary_matrix_is_deterministic(self) -> None:
        first = sampling.derive_binary_matrix(b"seed", (4, 100))
        second = sampling.derive_binary_matrix(b"seed", (4, 100))
        other = sampling.derive_binary_matrix(b"other", (4, 100))
        self.assertTrue(np.array_equal(first, second))
        self.assertFalse(np.array_equal(first, other))

    def test_bit_codec_rejects_nonzero_padding(self) -> None:
        encoded = base64.b64encode(bytes([0xFF])).decode("ascii")
        with self.assertRaises(InvalidProtocolDataError):
            codec.decode_bits(encoded, "s", 4)


if __name__ == "__main__":
    unittest.main()
