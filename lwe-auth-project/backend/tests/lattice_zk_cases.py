"""Shared test cases for candidates built on ``LatticeZKProtocol``.

Not collected directly (the file name does not match ``test*.py``); each
candidate's test module mixes ``LatticeZKProtocolCases`` into a TestCase.
"""

import base64
import copy

import numpy as np

from benchmarking.serialization import canonical_json_bytes
from crypto_core.exceptions import InvalidProtocolDataError
from crypto_core.lwe import codec


def flip_first_byte(encoded: str) -> str:
    raw = bytearray(base64.b64decode(encoded))
    raw[0] ^= 1
    return base64.b64encode(bytes(raw)).decode("ascii")


class LatticeZKProtocolCases:
    protocol_class: type
    # Small but valid parameters keep the suite fast; defaults are covered separately.
    small_parameters: dict
    # Valid parameters that differ from ``small_parameters``.
    alternative_parameters: dict
    shared_field: str
    public_field: str
    witness_fields: tuple
    expected_defaults: dict
    invalid_overrides: tuple

    def setUp(self) -> None:
        self.protocol = self.protocol_class()
        self.parameters = self.protocol.resolve_parameters(self.small_parameters)
        self.system_parameters = self.protocol.generate_system_parameters(**self.parameters)
        self.public_key, self.private_key = self.protocol.generate_keypair(
            self.system_parameters,
            **self.parameters,
        )

    def _prove(self, challenge=None, private_key=None):
        challenge = challenge or self.protocol.generate_challenge(
            self.system_parameters,
            self.public_key,
        )
        response = self.protocol.solve_challenge(
            self.system_parameters,
            private_key or self.private_key,
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

    def _rejected(self, challenge, response, public_key=None) -> bool:
        try:
            return not self._verify(challenge, response, public_key)
        except InvalidProtocolDataError:
            return True

    # -- completeness -----------------------------------------------------------

    def test_round_trip_is_valid(self) -> None:
        for _ in range(20):
            self.assertTrue(self._verify(*self._prove()))

    def test_round_trip_with_default_parameters(self) -> None:
        parameters = self.protocol.resolve_parameters()
        system_parameters = self.protocol.generate_system_parameters(**parameters)
        public_key, private_key = self.protocol.generate_keypair(system_parameters, **parameters)
        challenge = self.protocol.generate_challenge(system_parameters, public_key)
        response = self.protocol.solve_challenge(system_parameters, private_key, challenge)
        self.assertTrue(
            self.protocol.verify_response(system_parameters, public_key, challenge, response)
        )

    # -- soundness / binding ------------------------------------------------------

    def test_challenge_is_a_fresh_nonce(self) -> None:
        first = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        second = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        self.assertEqual(set(first), {"nonce"})
        self.assertNotEqual(first, second)

    def test_proof_does_not_verify_under_another_nonce(self) -> None:
        _, response = self._prove()
        other = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        self.assertFalse(self._verify(other, response))

    def test_proof_does_not_verify_under_another_public_key(self) -> None:
        challenge, response = self._prove()
        other_public, _ = self.protocol.generate_keypair(self.system_parameters, **self.parameters)
        self.assertFalse(self._verify(challenge, response, other_public))

    def test_other_private_key_does_not_convince_verifier(self) -> None:
        _, other_private = self.protocol.generate_keypair(self.system_parameters, **self.parameters)
        challenge, response = self._prove(private_key=other_private)
        self.assertFalse(self._verify(challenge, response))

    def test_every_modified_response_field_is_rejected(self) -> None:
        challenge, response = self._prove()
        for name in response:
            with self.subTest(field=name):
                tampered = dict(response, **{name: flip_first_byte(response[name])})
                self.assertTrue(self._rejected(challenge, tampered))

    def test_response_coefficient_above_norm_bound_is_rejected(self) -> None:
        challenge, response = self._prove()
        component = self.protocol._response_layout(self.protocol._context(self.system_parameters))[0]
        values = codec.decode_signed(response[component.name], component.name, component.shape, component.bound)
        oversized = values.copy()
        oversized[0] = component.bound + 1
        tampered = dict(
            response,
            **{component.name: codec.encode_signed(oversized, component.bound + 1)},
        )
        self.assertTrue(self._rejected(challenge, tampered))

    def test_random_response_is_rejected(self) -> None:
        challenge, response = self._prove()
        layout = self.protocol._response_layout(self.protocol._context(self.system_parameters))
        forged = {"c": response["c"]}
        for component in layout:
            random_values = np.random.default_rng().integers(
                -component.bound, component.bound + 1, component.shape
            )
            forged[component.name] = codec.encode_signed(random_values, component.bound)
        self.assertFalse(self._verify(challenge, forged))

    # -- zero knowledge (statistical sanity checks) -----------------------------

    def test_responses_are_uniform_on_the_box_independently_of_the_witness(self) -> None:
        # Rejection sampling must make z uniform on [-(gamma - beta), gamma - beta]:
        # mean ~ 0 and standard deviation ~ bound / sqrt(3), whatever the secret.
        context = self.protocol._context(self.system_parameters)
        layout = self.protocol._response_layout(context)
        samples = {component.name: [] for component in layout}
        for _ in range(30):
            _, response = self._prove()
            for component in layout:
                samples[component.name].append(
                    codec.decode_signed(
                        response[component.name],
                        component.name,
                        component.shape,
                        component.bound,
                    )
                )
        for component in layout:
            values = np.concatenate(samples[component.name]).astype(np.float64)
            with self.subTest(component=component.name):
                # >= 3840 samples: tolerances are > 4 standard errors.
                self.assertLess(abs(values.mean()) / component.bound, 0.04)
                self.assertAlmostEqual(
                    values.std() / component.bound,
                    1 / np.sqrt(3),
                    delta=0.02,
                )

    def test_two_proofs_for_the_same_nonce_differ(self) -> None:
        challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        _, first = self._prove(challenge)
        _, second = self._prove(challenge)
        self.assertNotEqual(first, second)
        self.assertTrue(self._verify(challenge, first))
        self.assertTrue(self._verify(challenge, second))

    def test_response_does_not_contain_witness_material(self) -> None:
        _, response = self._prove()
        for name in self.witness_fields:
            self.assertNotIn(self.private_key[name], response.values())

    # -- malformed inputs ---------------------------------------------------------

    def test_malformed_private_key_is_rejected(self) -> None:
        challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        first_witness = self.witness_fields[0]
        for private_key in (
            {**self.private_key, first_witness: "not-base64!"},
            {k: v for k, v in self.private_key.items() if k != first_witness},
            {**self.private_key, "public_key_digest": "AAAA"},
            "not-a-mapping",
        ):
            with self.subTest(private_key=str(private_key)[:40]):
                with self.assertRaises(InvalidProtocolDataError):
                    self.protocol.solve_challenge(self.system_parameters, private_key, challenge)

    def test_witness_outside_its_distribution_is_rejected(self) -> None:
        challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        name = self.witness_fields[-1]
        raw = bytearray(base64.b64decode(self.private_key[name]))
        raw[0] = 0xFF
        malformed = {**self.private_key, name: base64.b64encode(bytes(raw)).decode("ascii")}
        with self.assertRaises(InvalidProtocolDataError):
            self.protocol.solve_challenge(self.system_parameters, malformed, challenge)

    def test_malformed_public_key_and_challenge_are_rejected(self) -> None:
        challenge, response = self._prove()
        with self.assertRaises(InvalidProtocolDataError):
            self._verify(challenge, response, {self.public_field: "AAAA"})
        with self.assertRaises(InvalidProtocolDataError):
            self._verify({"nonce": "AAAA"}, response)
        with self.assertRaises(InvalidProtocolDataError):
            self._verify(challenge, {k: v for k, v in response.items() if k != "c"})

    # -- parameters ---------------------------------------------------------------

    def test_effective_parameters_are_explicit(self) -> None:
        resolved = self.protocol.resolve_parameters()
        self.assertEqual(resolved, self.protocol.default_parameters())
        self.assertEqual(resolved["proof_system"], "fiat_shamir_with_aborts")
        for key, value in self.expected_defaults.items():
            with self.subTest(parameter=key):
                self.assertEqual(resolved[key], value)

    def test_invalid_parameters_are_rejected(self) -> None:
        common_invalid = (
            {"unknown": 1},
            {"n": True},
            {"kappa": 5},
            {"gamma": 1000},
            {"gamma": 1 << 22},
            {"q": 1 << 25},
            {"proof_system": "none"},
            {"hash": "sha256"},
        )
        for overrides in common_invalid + tuple(self.invalid_overrides):
            with self.subTest(overrides=overrides):
                with self.assertRaises(InvalidProtocolDataError):
                    self.protocol.resolve_parameters(overrides)

    # -- setup / serialization / mutation -------------------------------------------

    def test_system_parameters_carry_shared_material_and_effective_parameters(self) -> None:
        self.assertEqual(self.system_parameters["protocol"], self.protocol.name)
        self.assertEqual(self.system_parameters["parameters"], self.parameters)
        self.assertIn(self.shared_field, self.system_parameters)

    def test_setup_generates_fresh_shared_material(self) -> None:
        other = self.protocol.generate_system_parameters(**self.parameters)
        self.assertNotEqual(other[self.shared_field], self.system_parameters[self.shared_field])

    def test_keygen_rejects_parameters_different_from_setup(self) -> None:
        with self.assertRaises(InvalidProtocolDataError):
            self.protocol.generate_keypair(self.system_parameters, **self.alternative_parameters)

    def test_system_parameters_of_another_protocol_are_rejected(self) -> None:
        foreign = dict(self.system_parameters, protocol="ecdsa")
        with self.assertRaises(InvalidProtocolDataError):
            self.protocol.generate_challenge(foreign, self.public_key)

    def test_non_canonical_system_parameters_are_rejected(self) -> None:
        parameters = dict(self.parameters)
        del parameters["proof_system"]
        altered = dict(self.system_parameters, parameters=parameters)
        with self.assertRaises(InvalidProtocolDataError):
            self.protocol.generate_challenge(altered, self.public_key)

    def test_all_artifacts_are_json_serializable(self) -> None:
        challenge, response = self._prove()
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
        _, response = self._prove(challenge)
        original_response = copy.deepcopy(response)
        self._verify(challenge, response)
        self.assertEqual((self.system_parameters, self.public_key, self.private_key), originals)
        self.assertEqual(challenge, original_challenge)
        self.assertEqual(response, original_response)
