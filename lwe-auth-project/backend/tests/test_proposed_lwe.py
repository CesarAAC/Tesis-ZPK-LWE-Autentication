"""Tests for PQLite-Auth v2 (``proposed_lwe``) in its dual-modulus form.

Grouped as: parameters, primitives (with the high/low-bits decomposition), the
behaviours required from the authentication flow, the rejection sampling, the
session-key agreement, the points where the implementation departs from the
manuscript (with the evidence for each), the reason for the second modulus, and
the evidence about zero knowledge.
"""

import base64
import copy
import hashlib
import importlib.util
import json
import secrets
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import numpy as np

from benchmarking.conformance import run_conformance_checks
from benchmarking.serialization import canonical_json_bytes
from crypto_core import token_hiding
from crypto_core.exceptions import CryptoCoreError, InvalidProtocolDataError
from crypto_core.lwe import codec, decomposition, module, reconciliation, ring, sampling
from crypto_core.protocols import proposed_lwe
from crypto_core.protocols.proposed_lwe import ProposedLWEAuthProtocol

Q = proposed_lwe.MODULUS
QP = proposed_lwe.PROOF_MODULUS
D = proposed_lwe.DEGREE
K = proposed_lwe.RANK
ETA = proposed_lwe.ETA
GAMMA1 = proposed_lwe.DEFAULT_GAMMA1
GAMMA2 = proposed_lwe.DEFAULT_GAMMA2
RESIDUES = np.arange(Q)


class FakeClock:
    def __init__(self, now: float = 1_800_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _flip_first_byte(encoded: str) -> str:
    raw = bytearray(base64.b64decode(encoded))
    raw[0] ^= 1
    return base64.b64encode(bytes(raw)).decode("ascii")


def _nudge(response: np.ndarray) -> np.ndarray:
    """Move one coefficient one step towards zero: still in range, no longer the proof."""
    nudged = response.copy()
    nudged[0, 0] += -1 if nudged[0, 0] > 0 else 1
    return nudged


def _multiply(left: np.ndarray, right: np.ndarray) -> np.ndarray:
    return ring.negacyclic_multiply(left, right, Q)


def _solve_mod(matrix: np.ndarray, rhs: np.ndarray) -> np.ndarray | None:
    """Solve matrix * x = rhs over F_q by Gauss-Jordan; None when singular."""
    size = matrix.shape[0]
    augmented = np.concatenate([matrix % Q, rhs.reshape(size, -1) % Q], axis=1).astype(np.int64)
    for column in range(size):
        pivots = np.nonzero(augmented[column:, column])[0]
        if pivots.size == 0:
            return None
        pivot = column + int(pivots[0])
        if pivot != column:
            augmented[[column, pivot]] = augmented[[pivot, column]]
        augmented[column] = (augmented[column] * pow(int(augmented[column, column]), -1, Q)) % Q
        factors = augmented[:, column].copy()
        factors[column] = 0
        augmented = (augmented - factors[:, None] * augmented[column][None, :]) % Q
    return augmented[:, size:]


def _ring_inverse(element: np.ndarray) -> np.ndarray | None:
    """Inverse of a ring element in Z_q[x]/(x^d + 1); None when it is not a unit."""
    rotation = np.empty((D, D), dtype=np.int64)
    for shift in range(D):
        rotation[:, shift] = (
            np.concatenate([-element[D - shift:], element[: D - shift]]) if shift else element
        )
    unit = np.zeros(D, dtype=np.int64)
    unit[0] = 1
    solution = _solve_mod(rotation, unit)
    return None if solution is None else solution[:, 0]


def _matrix_inverse(matrix: np.ndarray) -> np.ndarray | None:
    """Inverse of a 3 x 3 matrix over the ring through its adjugate."""
    adjugate = np.empty_like(matrix)
    for i in range(3):
        for j in range(3):
            row_a, row_b = (j + 1) % 3, (j + 2) % 3
            column_a, column_b = (i + 1) % 3, (i + 2) % 3
            adjugate[i, j] = (
                _multiply(matrix[row_a, column_a], matrix[row_b, column_b])
                - _multiply(matrix[row_a, column_b], matrix[row_b, column_a])
            ) % Q
    determinant = sum(_multiply(matrix[0, j], adjugate[j, 0]) for j in range(3)) % Q
    determinant_inverse = _ring_inverse(determinant)
    if determinant_inverse is None:
        return None
    return np.stack(
        [np.stack([_multiply(determinant_inverse, adjugate[i, j]) for j in range(3)]) for i in range(3)]
    )


def _least_squares_estimate(pairs) -> np.ndarray:
    """Least-squares solution of z_i = c_i s + noise_i for s, given pairs (c_i, z_i).

    Evaluating at the odd 2d-th roots of unity turns negacyclic products into
    pointwise products, so the normal equations are diagonal.
    """
    rotation = np.exp(1j * np.pi * np.arange(D) / D)

    def spectrum(polynomial):
        return np.fft.fft(np.asarray(polynomial, dtype=np.float64) * rotation)

    numerator = 0
    weight = np.zeros(D)
    for challenge, response in pairs:
        challenge_spectrum = spectrum(challenge)
        weight += np.abs(challenge_spectrum) ** 2
        numerator = numerator + np.conj(challenge_spectrum) * np.stack(
            [spectrum(component) for component in response]
        )
    return np.real(np.fft.ifft(numerator / weight, axis=1) / rotation)


class _Deployment(unittest.TestCase):
    """One verifier deployment and one enrolled client with the given open values."""

    overrides: dict = {}

    def setUp(self) -> None:
        self.clock = FakeClock()
        self.protocol = ProposedLWEAuthProtocol(clock=self.clock)
        self.parameters = self.protocol.resolve_parameters(self.overrides)
        self.rank = self.parameters["k_proof"]
        self.system_parameters = self.protocol.generate_system_parameters(**self.parameters)
        self.public_key, self.private_key = self.protocol.generate_keypair(
            self.system_parameters,
            **self.parameters,
        )

    def _authenticate(self, private_key=None):
        challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
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

    def _internals(self):
        context = self.protocol._context(self.system_parameters)
        matrix, matrix_digest = self.protocol._proof_matrix(context)
        secret, error, public_key_digest = self.protocol._witness(context, self.private_key)
        return context, matrix, matrix_digest, secret, error, public_key_digest

    def _public_vector(self) -> np.ndarray:
        context = self.protocol._context(self.system_parameters)
        return self.protocol._public_vector(context, self.public_key)[1]

    def _proof(self, challenge):
        """Run the prover; return (z, c~, c), i.e. what the verifier holds after decrypting."""
        context, matrix, matrix_digest, secret, error, public_key_digest = self._internals()
        ticket, nu = self.protocol._parse_challenge(challenge)
        response, seed, _ = self.protocol._prove(
            context, matrix, matrix_digest, secret, error, public_key_digest, ticket, nu
        )
        return response, seed, self.protocol._challenge_polynomial(context, seed)

    def _token(self, challenge, response, seed):
        """Seal an arbitrary (z, c~) for this verifier, as any sender can."""
        context = self.protocol._context(self.system_parameters)
        ticket, nu = self.protocol._parse_challenge(challenge)
        return self.protocol._seal_token(context, response, seed, ticket, nu)

    def _rebuilt(self, response, challenge_polynomial) -> np.ndarray:
        """A' z - c t mod q', the value whose high bits the verifier hashes."""
        _, matrix, _, _, _, _ = self._internals()
        return (
            module.matrix_vector(matrix, response, QP)
            - module.scale_vector(challenge_polynomial, self._public_vector(), QP)
        ) % QP

    def _attempt(self, challenge) -> SimpleNamespace:
        """One prover attempt computed step by step, without applying the rejections."""
        context, matrix, matrix_digest, secret, error, public_key_digest = self._internals()
        ticket, nu = self.protocol._parse_challenge(challenge)
        gamma1, gamma2, beta = (self.parameters[name] for name in ("gamma1", "gamma2", "beta"))
        alpha = 2 * gamma2
        mask = sampling.sample_uniform_box((self.rank, D), gamma1 - 1)
        commitment = module.matrix_vector(matrix, mask, QP)
        high = decomposition.high_bits(commitment, alpha, QP)
        seed = self.protocol._challenge_seed(
            context, matrix_digest, public_key_digest, high, ticket, nu
        )
        challenge_polynomial = self.protocol._challenge_polynomial(context, seed)
        response = mask + module.centered(
            module.scale_vector(challenge_polynomial, secret, QP), QP
        )
        shifted = (commitment - module.scale_vector(challenge_polynomial, error, QP)) % QP
        low = decomposition.low_bits(shifted, alpha, QP)
        return SimpleNamespace(
            commitment=commitment,
            high=high,
            seed=seed,
            challenge=challenge_polynomial,
            response=response,
            shifted=shifted,
            response_ok=int(np.abs(response).max()) < gamma1 - beta,
            low_ok=int(np.abs(low).max()) < gamma2 - beta,
            # y + c s can leave [-gamma1, gamma1), the range the token encoding holds.
            encodable=-gamma1 <= int(response.min()) and int(response.max()) < gamma1,
        )

    def _attempt_where(self, condition, limit: int = 3000):
        """Return (challenge, attempt) for the first attempt satisfying ``condition``."""
        for _ in range(limit):
            challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
            attempt = self._attempt(challenge)
            if condition(attempt):
                return challenge, attempt
        self.fail(f"no attempt satisfied the condition in {limit} tries")

    def _forget_spent_tickets(self) -> None:
        """Test only: empty the verifier's logs so one transcript can be checked twice."""
        context = self.protocol._context(self.system_parameters)
        state = proposed_lwe._KEYSTORE.get(context.verifier_key_id)
        with state.lock:
            state.spent.clear()
            state.authenticated.clear()


class ParameterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.protocol = ProposedLWEAuthProtocol()

    def test_manuscript_vector_and_proof_modulus(self) -> None:
        parameters = self.protocol.resolve_parameters()
        self.assertEqual(parameters, self.protocol.default_parameters())
        self.assertEqual(
            (parameters["d"], parameters["k"], parameters["q"], parameters["eta"]),
            (256, 3, 3329, 2),
        )
        self.assertEqual(parameters["q_proof"], 8380417)
        self.assertEqual(parameters["q_proof"].bit_length(), 23)
        self.assertEqual(parameters["kem"], "ML-KEM-768")
        self.assertEqual(parameters["aead"], "AES-256-GCM")
        self.assertEqual(parameters["proof_system"], "fiat_shamir_with_aborts_high_bits")

    def test_fixed_parameters_cannot_be_changed(self) -> None:
        for overrides in (
            {"q": 12289},
            {"q": 8380417},
            {"q": 3329.0},
            {"q_proof": 3329},
            {"q_proof": 8380417.0},
            {"d": 128},
            {"k": 2},
            {"eta": 3},
            {"kem": "ML-KEM-512"},
            {"challenge_distribution": "uniform"},
            {"masking_distribution": "centered_binomial"},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises(InvalidProtocolDataError):
                    self.protocol.resolve_parameters(overrides)
        self.assertEqual(
            self.protocol.resolve_parameters(
                {"d": 256, "k": 3, "q": 3329, "eta": 2, "q_proof": 8380417}
            ),
            self.protocol.resolve_parameters(),
        )

    def test_open_values_have_documented_defaults(self) -> None:
        parameters = self.protocol.resolve_parameters()
        # Chosen by the authors on 2026-10-04; the manuscript's k = 3 stays available.
        self.assertEqual(parameters["k_proof"], 4)
        self.assertEqual(parameters["kappa"], 23)
        self.assertEqual(parameters["beta"], ETA * 23)
        self.assertEqual(parameters["gamma1"], 1 << 17)
        self.assertEqual(parameters["gamma2"], (QP - 1) // 88)
        self.assertEqual(parameters["time_window_seconds"], 300)
        # 23 is the smallest weight with at least 2^128 challenges in degree 256.
        self.assertGreaterEqual(proposed_lwe.challenge_space_bits(D, 23), 128)
        self.assertLess(proposed_lwe.challenge_space_bits(D, 22), 128)

    def test_beta_is_derived_from_the_challenge_weight(self) -> None:
        self.assertEqual(self.protocol.resolve_parameters({"kappa": 30})["beta"], 60)
        self.assertEqual(self.protocol.resolve_parameters({"beta": 46})["beta"], 46)
        for overrides in ({"beta": 47}, {"beta": 46.0}, {"kappa": 30, "beta": 46}):
            with self.subTest(overrides=overrides):
                with self.assertRaises(InvalidProtocolDataError):
                    self.protocol.resolve_parameters(overrides)

    def test_open_values_can_be_set_explicitly(self) -> None:
        parameters = self.protocol.resolve_parameters(
            {
                "k_proof": 4,
                "gamma1": 1 << 19,
                "gamma2": (QP - 1) // 32,
                "time_window_seconds": 30,
            }
        )
        self.assertEqual(
            (
                parameters["k_proof"],
                parameters["gamma1"],
                parameters["gamma2"],
                parameters["time_window_seconds"],
            ),
            (4, 524288, 261888, 30),
        )

    def test_invalid_open_values_are_rejected(self) -> None:
        for overrides in (
            {"unknown": 1},
            {"beta_z": 48},
            {"kappa": 22},
            {"kappa": True},
            {"kappa": 257},
            {"k_proof": 2},
            {"k_proof": 9},
            {"k_proof": 3.0},
            {"gamma1": 46},
            {"gamma1": 1 << 20},
            {"gamma1": 131072.0},
            {"gamma2": 46},
            {"gamma2": GAMMA2 + 1},
            {"gamma2": (QP - 1) // 16},
            {"time_window_seconds": 0},
            {"time_window_seconds": 86_401},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises(InvalidProtocolDataError):
                    self.protocol.resolve_parameters(overrides)

    def test_parameter_sets_whose_prover_would_rarely_finish_are_rejected(self) -> None:
        self.assertEqual((QP - 1) % (2 * 4092), 0)
        for overrides in ({"gamma1": 4096}, {"gamma2": 4092}, {"kappa": 60, "gamma1": 1 << 14}):
            with self.subTest(overrides=overrides):
                with self.assertRaises(InvalidProtocolDataError):
                    self.protocol.resolve_parameters(overrides)

    def test_predicted_acceptance_per_attempt(self) -> None:
        self.assertAlmostEqual(
            proposed_lwe.acceptance_probability(3, GAMMA1, GAMMA2, 46), 0.5248, delta=0.0005
        )
        self.assertAlmostEqual(
            proposed_lwe.acceptance_probability(4, GAMMA1, GAMMA2, 46), 0.4233, delta=0.0005
        )
        # ML-DSA-44 itself (rank 4, beta = 78): its specification rounds this to 4.25.
        self.assertAlmostEqual(
            1 / proposed_lwe.acceptance_probability(4, GAMMA1, GAMMA2, 78), 4.25, delta=0.05
        )


class PrimitiveTests(unittest.TestCase):
    def test_cbd_bounds_and_distribution(self) -> None:
        samples = sampling.sample_centered_binomial((200_000,), ETA)
        self.assertEqual((int(samples.min()), int(samples.max())), (-ETA, ETA))
        self.assertLess(abs(float(samples.mean())), 0.02)
        self.assertAlmostEqual(float(samples.var()), ETA / 2, delta=0.02)
        frequencies = np.bincount(samples + ETA, minlength=5) / samples.size
        np.testing.assert_allclose(frequencies, [1 / 16, 4 / 16, 6 / 16, 4 / 16, 1 / 16], atol=0.008)

    def test_uniform_mask_covers_exactly_its_box(self) -> None:
        samples = sampling.sample_uniform_box((400_000,), 7)
        self.assertEqual((int(samples.min()), int(samples.max())), (-7, 7))
        frequencies = np.bincount(samples + 7, minlength=15) / samples.size
        np.testing.assert_allclose(frequencies, np.full(15, 1 / 15), atol=0.003)

    def test_matrix_expansion_is_deterministic_and_in_range(self) -> None:
        seed = bytes(range(32))
        for modulus in (Q, QP):
            with self.subTest(modulus=modulus):
                first = module.expand_uniform_matrix(seed, K, K, D, modulus)
                second = module.expand_uniform_matrix(seed, K, K, D, modulus)
                other = module.expand_uniform_matrix(bytes(32), K, K, D, modulus)
                self.assertEqual(first.shape, (K, K, D))
                np.testing.assert_array_equal(first, second)
                self.assertFalse(np.array_equal(first, other))
                self.assertGreaterEqual(int(first.min()), 0)
                self.assertLess(int(first.max()), modulus)
                self.assertEqual(
                    len({first[i, j].tobytes() for i in range(K) for j in range(K)}), K * K
                )
                self.assertLess(abs(float(first.mean()) / modulus - 0.5), 0.03)

    def test_matrix_expansion_layout_is_pinned_by_known_answers(self) -> None:
        # A change of byte layout would silently change the matrix of every deployment.
        seed = bytes(range(32))
        known = {
            Q: (
                [481, 2808, 2046, 1434],
                "adad2003a6f9d36181d7ca99ab1d54033eed8fd6a6a5c11dc407c0e9d9a6fa27",
            ),
            QP: (
                [7905761, 7863978, 1275290, 4366663],
                "ab43c171c70227f474202c185adf9d4018eb431ee1129a7003194881471f2102",
            ),
        }
        for modulus, (first_coefficients, digest) in known.items():
            with self.subTest(modulus=modulus):
                matrix = module.expand_uniform_matrix(seed, K, K, D, modulus)
                self.assertEqual(matrix[0, 0, :4].tolist(), first_coefficients)
                self.assertEqual(
                    hashlib.sha256(matrix.astype("<i8").tobytes()).hexdigest(), digest
                )

    def test_matrix_expansion_rejects_moduli_above_24_bits(self) -> None:
        self.assertEqual(module.expand_uniform_matrix(bytes(32), 1, 1, 8, 1 << 24).shape, (1, 1, 8))
        with self.assertRaises(ValueError):
            module.expand_uniform_matrix(bytes(32), 1, 1, 8, (1 << 24) + 1)

    def test_bit_packing_round_trips_at_every_width_in_use(self) -> None:
        cases = {
            "transport coefficients": (Q, 12, [0, 1, Q - 1, 2048]),
            "proof coefficients": (QP, 23, [0, 1, QP - 1, 1 << 22]),
            "responses": (2 * GAMMA1, 18, [0, 1, 2 * GAMMA1 - 1, GAMMA1]),
            "secrets": (2 * ETA + 1, 3, [0, 1, 2 * ETA, ETA]),
            "high bits": ((QP - 1) // (2 * GAMMA2), 6, [0, 1, 43, 22]),
        }
        for label, (modulus, bits, edge_values) in cases.items():
            with self.subTest(label):
                self.assertEqual(codec.packed_bits(modulus), bits)
                vector = sampling.sample_uniform_mod_q((K, D), modulus)
                vector[0, :4] = edge_values
                raw = codec.pack_coefficients(vector, modulus)
                self.assertEqual(len(raw), K * D * bits // 8)
                np.testing.assert_array_equal(
                    codec.unpack_coefficients(raw, "v", (K, D), modulus), vector
                )

    def test_packing_rejects_wrong_length_and_out_of_range_coefficients(self) -> None:
        raw = bytearray(codec.pack_coefficients(np.zeros(D, dtype=np.int64), Q))
        with self.assertRaises(InvalidProtocolDataError):
            codec.unpack_coefficients(bytes(raw[:-1]), "v", (D,), Q)
        raw[0], raw[1] = 0xFF, 0x0F  # first coefficient = 4095 >= q
        with self.assertRaises(InvalidProtocolDataError):
            codec.unpack_coefficients(bytes(raw), "v", (D,), Q)
        wide = bytearray(codec.pack_coefficients(np.zeros(D, dtype=np.int64), QP))
        wide[0], wide[1], wide[2] = 0xFF, 0xFF, 0x7F  # first coefficient = 2^23 - 1 >= q'
        with self.assertRaises(InvalidProtocolDataError):
            codec.unpack_coefficients(bytes(wide), "v", (D,), QP)

    def test_module_arithmetic_matches_a_naive_reference(self) -> None:
        degree, modulus, rank = 8, 17, 2
        rng = np.random.default_rng(11)
        matrix = rng.integers(0, modulus, size=(rank, rank, degree))
        vector = rng.integers(-2, 3, size=(rank, degree))
        other = rng.integers(0, modulus, size=(rank, degree))

        def naive(left, right):
            product = np.zeros(degree, dtype=np.int64)
            for i in range(degree):
                for j in range(degree):
                    sign = 1 if i + j < degree else -1
                    product[(i + j) % degree] += sign * left[i] * right[j]
            return product

        expected = np.stack(
            [sum(naive(matrix[i, j], vector[j]) for j in range(rank)) % modulus for i in range(rank)]
        )
        np.testing.assert_array_equal(module.matrix_vector(matrix, vector, modulus), expected)
        np.testing.assert_array_equal(
            module.inner_product(other, vector, modulus),
            sum(naive(other[i], vector[i]) for i in range(rank)) % modulus,
        )
        np.testing.assert_array_equal(
            module.scale_vector(other[0], vector, modulus),
            np.stack([naive(other[0], vector[i]) % modulus for i in range(rank)]),
        )

    def test_products_at_the_proof_modulus_do_not_overflow_int64(self) -> None:
        # Worst case of the protocol and beyond: every coefficient at q' - 1 on both sides.
        extreme = np.full(D, QP - 1, dtype=np.int64)
        uniform = sampling.sample_uniform_mod_q((D,), QP)

        def exact(left, right):
            left, right = [int(v) for v in left], [int(v) for v in right]
            product = [0] * D
            for i in range(D):
                for j in range(D):
                    if i + j < D:
                        product[i + j] += left[i] * right[j]
                    else:
                        product[i + j - D] -= left[i] * right[j]
            return [value % QP for value in product]

        for left, right in ((extreme, extreme), (uniform, extreme), (uniform, -extreme)):
            self.assertEqual(ring.negacyclic_multiply(left, right, QP).tolist(), exact(left, right))

    def test_transposed_matrix_gives_the_key_agreement_identity(self) -> None:
        # (A s)^T r = s^T (A^T r): the two sides of the session-key computation.
        matrix = module.expand_uniform_matrix(bytes(range(32)), K, K, D, Q)
        left = sampling.sample_centered_binomial((K, D), ETA)
        right = sampling.sample_centered_binomial((K, D), ETA)
        np.testing.assert_array_equal(
            module.inner_product(module.matrix_vector(matrix, left, Q), right, Q),
            module.inner_product(
                left,
                module.matrix_vector(module.transpose(matrix), right, Q),
                Q,
            ),
        )

    @unittest.skipUnless(importlib.util.find_spec("sage"), "SageMath is not installed")
    def test_ring_arithmetic_matches_sagemath_quotient_ring_for_both_moduli(self) -> None:
        # Runs in its own interpreter: importing sage.all is slow and alters global state.
        script = textwrap.dedent(
            """
            import secrets
            from sage.all import GF, PolynomialRing, matrix, vector
            from crypto_core.lwe import module, sampling

            d, k = 256, 3
            for q in (3329, 8380417):
                base = PolynomialRing(GF(q), "X")
                quotient = base.quotient(base.gen() ** d + 1, "x")
                to_sage = lambda poly: quotient([int(c) % q for c in poly])
                coefficients = lambda element: [int(c) for c in element.list()]

                A = module.expand_uniform_matrix(secrets.token_bytes(32), k, k, d, q)
                s = sampling.sample_centered_binomial((k, d), 2)
                e = sampling.sample_centered_binomial((k, d), 2)
                r = sampling.sample_uniform_box((k, d), 131071)
                c = sampling.derive_sparse_ternary(secrets.token_bytes(32), d, 23)
                t = (module.matrix_vector(A, s, q) + e) % q
                A_sage = matrix(quotient, k, k, [to_sage(A[i, j]) for i in range(k) for j in range(k)])
                t_sage = A_sage * vector(quotient, [to_sage(p) for p in s]) + vector(quotient, [to_sage(p) for p in e])
                assert all(coefficients(t_sage[i]) == [int(v) for v in t[i]] for i in range(k))
                wide_sage = A_sage * vector(quotient, [to_sage(p) for p in r])
                wide = module.matrix_vector(A, r, q)
                assert all(coefficients(wide_sage[i]) == [int(v) for v in wide[i]] for i in range(k))
                scaled = module.scale_vector(c, t, q)
                assert all(coefficients(to_sage(c) * t_sage[i]) == [int(v) for v in scaled[i]] for i in range(k))
                inner_sage = sum(t_sage[i] * to_sage(r[i]) for i in range(k))
                assert coefficients(inner_sage) == [int(v) for v in module.inner_product(t, r, q)]
            print("SAGE-OK")
            """
        )
        completed = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=Path(__file__).resolve().parents[1],
        )
        self.assertEqual(completed.returncode, 0, completed.stderr[-2000:])
        self.assertIn("SAGE-OK", completed.stdout)


class DecompositionTests(unittest.TestCase):
    """HighBits / LowBits over the whole of Z_q' for the default rounding step."""

    alpha = 2 * GAMMA2
    beta = ETA * proposed_lwe.DEFAULT_KAPPA

    def _all_residues(self):
        chunk = 1 << 20
        for start in range(0, QP, chunk):
            yield np.arange(start, min(start + chunk, QP), dtype=np.int64)

    def test_rounding_step_divides_q_minus_one_into_44_values(self) -> None:
        self.assertEqual((QP - 1) % self.alpha, 0)
        self.assertEqual(decomposition.high_values(self.alpha, QP), 44)
        self.assertEqual(QP - 1, (1 << 13) * 1023)

    def test_decomposition_is_exact_for_every_residue(self) -> None:
        for residues in self._all_residues():
            high, low = decomposition.decompose(residues, self.alpha, QP)
            np.testing.assert_array_equal((high * self.alpha + low) % QP, residues)
            self.assertGreaterEqual(int(low.min()), -GAMMA2)
            self.assertLessEqual(int(low.max()), GAMMA2)
            self.assertGreaterEqual(int(high.min()), 0)
            self.assertLessEqual(int(high.max()), 43)

    def test_top_interval_is_folded_onto_high_value_zero(self) -> None:
        values = np.array([0, 1, GAMMA2, GAMMA2 + 1, QP - 1 - GAMMA2, QP - GAMMA2, QP - 2, QP - 1])
        high, low = decomposition.decompose(values, self.alpha, QP)
        self.assertEqual(high.tolist(), [0, 0, 0, 1, 43, 0, 0, 0])
        self.assertEqual(low.tolist(), [0, 1, GAMMA2, -GAMMA2 + 1, GAMMA2, -GAMMA2, -2, -1])

    def test_high_bits_survive_a_shift_of_beta_when_the_low_bits_leave_room(self) -> None:
        # Lemma 2 of the Dilithium specification. HighBits is constant on arcs longer than
        # 2 beta, so equality at both extreme shifts settles every shift in between.
        rng = np.random.default_rng(7)
        safe_total = 0
        for residues in self._all_residues():
            high, low = decomposition.decompose(residues, self.alpha, QP)
            safe = np.abs(low) < GAMMA2 - self.beta
            safe_total += int(safe.sum())
            shifts = rng.integers(-self.beta, self.beta + 1, size=residues.size)
            for shift in (self.beta, -self.beta, shifts):
                shifted_high = decomposition.high_bits(residues + shift, self.alpha, QP)
                np.testing.assert_array_equal(shifted_high[safe], high[safe])
        # Fraction of Z_q' that passes the prover's low-bits test, per coefficient.
        self.assertAlmostEqual(
            safe_total / QP, (2 * (GAMMA2 - self.beta) - 1) / self.alpha, delta=1e-5
        )

    def test_without_that_room_a_shift_of_beta_can_change_the_high_bits(self) -> None:
        boundary = np.array([GAMMA2, GAMMA2 - self.beta, 3 * GAMMA2 - self.beta + 1])
        _, low = decomposition.decompose(boundary, self.alpha, QP)
        self.assertTrue((np.abs(low) >= GAMMA2 - self.beta).all())
        self.assertFalse(
            np.array_equal(
                decomposition.high_bits(boundary + self.beta, self.alpha, QP),
                decomposition.high_bits(boundary, self.alpha, QP),
            )
        )

    def test_invalid_rounding_steps_are_rejected(self) -> None:
        for alpha in (0, 3, self.alpha + 2, 2 * 95233):
            with self.subTest(alpha=alpha):
                with self.assertRaises(ValueError):
                    decomposition.decompose(np.arange(4), alpha, QP)


class ReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = reconciliation.modular_round(RESIDUES, Q)
        self.hint = reconciliation.cross_round(RESIDUES, Q)

    def _reconcile(self, error: int) -> np.ndarray:
        return reconciliation.reconcile((RESIDUES + error) % Q, self.hint, Q)

    def test_rounding_functions_match_the_manuscript_formulas(self) -> None:
        np.testing.assert_array_equal(self.key, np.floor(2 * RESIDUES / Q + 0.5).astype(int) % 2)
        np.testing.assert_array_equal(self.hint, np.floor(4 * RESIDUES / Q).astype(int) % 2)

    def test_agreement_is_exact_for_every_input_and_every_error_up_to_415(self) -> None:
        for error in range(-415, 416):
            if not np.array_equal(self._reconcile(error), self.key):
                self.fail(f"reconciliation failed for error {error}")

    def test_agreement_is_not_guaranteed_at_416_although_q_over_8_is_larger(self) -> None:
        self.assertGreater(Q / 8, 416)
        mismatches = sum(int((self._reconcile(error) != self.key).sum()) for error in (416, -416))
        self.assertGreater(mismatches, 0)

    def test_errors_beyond_q_over_8_fail_for_some_inputs_not_for_all(self) -> None:
        mismatch = self._reconcile(420) != self.key
        self.assertTrue(0 < int(mismatch.sum()) < Q)
        failing_input = int(np.flatnonzero(mismatch)[0])
        self.assertNotEqual(
            int(
                reconciliation.reconcile(
                    np.array([(failing_input + 420) % Q]),
                    np.array([self.hint[failing_input]]),
                    Q,
                )[0]
            ),
            int(self.key[failing_input]),
        )
        self.assertGreater(int((self._reconcile(Q // 4) != self.key).sum()), Q // 4)

    def test_random_noise_below_the_bound_always_gives_the_same_256_bits(self) -> None:
        rng = np.random.default_rng(2026)
        server_values = rng.integers(0, Q, size=(2000, D))
        noise = rng.integers(-415, 416, size=(2000, D))
        np.testing.assert_array_equal(
            reconciliation.reconcile(
                (server_values + noise) % Q,
                reconciliation.cross_round(server_values, Q),
                Q,
            ),
            reconciliation.modular_round(server_values, Q),
        )

    def test_hint_is_nearly_independent_of_the_key_bit(self) -> None:
        for hint_value in (0, 1):
            self.assertAlmostEqual(
                float(self.key[self.hint == hint_value].mean()), 0.5, delta=0.001
            )
        # Without Peikert's randomized doubling the bit is slightly biased for odd q.
        self.assertEqual(int((self.key == 0).sum()), 1665)

    def test_bits_pack_into_32_bytes(self) -> None:
        bits = sampling.sample_binary((D,))
        raw = reconciliation.bits_to_bytes(bits)
        self.assertEqual(len(raw), 32)
        np.testing.assert_array_equal(reconciliation.bytes_to_bits(raw, D), bits)


class AuthenticationFlowTests(_Deployment):
    # -- correctness ------------------------------------------------------------

    def test_honest_authentication_and_identical_256_bit_session_key(self) -> None:
        challenge, response = self._authenticate()
        self.assertTrue(self._verify(challenge, response))

        client_share, client_secret = self.protocol.generate_key_agreement_share(
            self.system_parameters, "client"
        )
        server_share, server_secret = self.protocol.generate_key_agreement_share(
            self.system_parameters, "server"
        )
        hint, server_key = self.protocol.generate_reconciliation_hint(
            self.system_parameters, challenge, client_share, server_secret
        )
        client_key = self.protocol.reconcile_session_key(
            self.system_parameters, server_share, client_secret, hint
        )
        self.assertEqual(client_key, server_key)
        self.assertEqual(len(client_key) * 8, 256)

    def test_every_honest_authentication_is_accepted(self) -> None:
        accepted = sum(self._verify(*self._authenticate()) for _ in range(100))
        self.assertEqual(accepted, 100)

    def test_honest_acceptance_does_not_depend_on_the_key_or_the_deployment(self) -> None:
        for _ in range(4):
            system_parameters = self.protocol.generate_system_parameters(**self.parameters)
            for _ in range(3):
                public_key, private_key = self.protocol.generate_keypair(
                    system_parameters, **self.parameters
                )
                for _ in range(10):
                    challenge = self.protocol.generate_challenge(system_parameters, public_key)
                    response = self.protocol.solve_challenge(system_parameters, private_key, challenge)
                    self.assertTrue(
                        self.protocol.verify_response(system_parameters, public_key, challenge, response)
                    )

    def test_keys_satisfy_the_public_relation_over_the_proof_modulus(self) -> None:
        # t = A' s + e mod q' with s, e in the CBD range (tex:61, moved to q').
        _, matrix, _, secret, error, _ = self._internals()
        public_vector = self._public_vector()
        self.assertEqual(matrix.shape, (self.rank, self.rank, D))
        self.assertLess(int(public_vector.max()), QP)
        self.assertGreater(int(public_vector.max()), Q)
        np.testing.assert_array_equal(
            module.centered(public_vector - module.matrix_vector(matrix, secret, QP), QP), error
        )
        self.assertLessEqual(int(np.abs(error).max()), ETA)
        self.assertLessEqual(int(np.abs(secret).max()), ETA)

    def test_proof_and_key_agreement_matrices_come_from_unrelated_streams(self) -> None:
        context, proof_matrix, _, _, _, _ = self._internals()
        agreement_matrix = self.protocol._agreement_matrix(context)
        self.assertEqual(agreement_matrix.shape, (K, K, D))
        self.assertLess(int(agreement_matrix.max()), Q)
        seed = base64.b64decode(self.system_parameters["rho"])
        np.testing.assert_array_equal(
            agreement_matrix, module.expand_uniform_matrix(seed, K, K, D, Q)
        )
        self.assertFalse(
            np.array_equal(proof_matrix, module.expand_uniform_matrix(seed, self.rank, self.rank, D, QP))
        )
        np.testing.assert_array_equal(proof_matrix, self.protocol._proof_matrix(context)[0])

    # -- freshness and ticket binding -------------------------------------------

    def test_challenges_are_fresh_single_use_tickets(self) -> None:
        first = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        second = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        self.assertEqual(set(first), {"ticket", "nu"})
        self.assertNotEqual(first["ticket"], second["ticket"])
        self.assertEqual(len(base64.b64decode(first["ticket"])), 32)
        self.assertEqual(first["nu"], int(self.clock.now * 1000))

    def test_proof_for_one_ticket_is_rejected_under_another(self) -> None:
        challenge_a, response_a = self._authenticate()
        challenge_b = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        self.assertFalse(self._verify(challenge_b, response_a))
        # The mismatch did not spend ticket A.
        self.assertTrue(self._verify(challenge_a, response_a))

    def test_proof_is_bound_to_the_timestamp(self) -> None:
        challenge, response = self._authenticate()
        shifted = dict(challenge, nu=challenge["nu"] + 1)
        self.assertFalse(self._verify(shifted, response))

    def test_ticket_and_timestamp_are_hashed_into_the_challenge(self) -> None:
        # Resealing a valid (z, c~) under another ticket or timestamp does not verify:
        # the binding comes from the hash, not only from the sealed copy of the pair.
        challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        response, seed, _ = self._proof(challenge)
        other_ticket = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        other_time = dict(challenge, nu=challenge["nu"] + 1)
        for label, target in (("ticket", other_ticket), ("timestamp", other_time)):
            with self.subTest(changed=label):
                self.assertFalse(self._verify(target, self._token(target, response, seed)))
        self._forget_spent_tickets()
        self.assertTrue(self._verify(challenge, self._token(challenge, response, seed)))

    # -- key binding -------------------------------------------------------------

    def test_proof_from_another_private_key_is_rejected(self) -> None:
        _, other_private = self.protocol.generate_keypair(self.system_parameters, **self.parameters)
        challenge, response = self._authenticate(private_key=other_private)
        self.assertFalse(self._verify(challenge, response))

    def test_proof_is_rejected_under_another_public_key(self) -> None:
        other_public, _ = self.protocol.generate_keypair(self.system_parameters, **self.parameters)
        challenge, response = self._authenticate()
        self.assertFalse(self._verify(challenge, response, other_public))

    def test_right_secret_with_another_public_key_digest_is_rejected(self) -> None:
        # H(t) enters the hash: the prover cannot answer for a different enrolled key.
        other_public, other_private = self.protocol.generate_keypair(
            self.system_parameters, **self.parameters
        )
        mixed = dict(self.private_key, public_key_digest=other_private["public_key_digest"])
        challenge, response = self._authenticate(private_key=mixed)
        self.assertFalse(self._verify(challenge, response))
        challenge, response = self._authenticate(private_key=mixed)
        self.assertFalse(self._verify(challenge, response, other_public))

    # -- replay ------------------------------------------------------------------

    def test_replayed_token_is_rejected_by_the_spent_log(self) -> None:
        challenge, response = self._authenticate()
        self.assertTrue(self._verify(challenge, response))
        self.assertFalse(self._verify(challenge, response))
        # The log belongs to the verifier process, not to one protocol object.
        self.assertFalse(
            ProposedLWEAuthProtocol(clock=self.clock).verify_response(
                self.system_parameters, self.public_key, challenge, response
            )
        )

    def test_ticket_is_spent_even_when_the_proof_is_invalid(self) -> None:
        # The manuscript adds the ticket to the log before checking the lattice equations.
        challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        response, seed, _ = self._proof(challenge)
        self.assertFalse(self._verify(challenge, self._token(challenge, _nudge(response), seed)))
        self.assertFalse(self._verify(challenge, self._token(challenge, response, seed)))

    # -- time window -------------------------------------------------------------

    def test_token_is_accepted_inside_the_time_window(self) -> None:
        challenge, response = self._authenticate()
        self.clock.advance(self.parameters["time_window_seconds"])
        self.assertTrue(self._verify(challenge, response))

    def test_token_is_rejected_after_the_time_window(self) -> None:
        challenge, response = self._authenticate()
        self.clock.advance(self.parameters["time_window_seconds"] + 1)
        self.assertFalse(self._verify(challenge, response))

    def test_timestamp_too_far_in_the_future_is_rejected(self) -> None:
        challenge, response = self._authenticate()
        self.clock.advance(-(self.parameters["time_window_seconds"] + 1))
        self.assertFalse(self._verify(challenge, response))

    # -- lattice checks ----------------------------------------------------------

    def test_verifier_rebuilds_w_minus_c_e_which_has_the_high_bits_of_w(self) -> None:
        beta = self.parameters["beta"]
        alpha = 2 * self.parameters["gamma2"]
        _, _, _, _, error, _ = self._internals()
        for _ in range(5):
            challenge, attempt = self._attempt_where(
                lambda attempt: attempt.response_ok and attempt.low_ok
            )
            self.assertEqual(int(np.count_nonzero(attempt.challenge)), self.parameters["kappa"])
            shift = module.centered(module.scale_vector(attempt.challenge, error, QP), QP)
            self.assertLessEqual(int(np.abs(shift).max()), beta)

            # A' z - c t = w - c e: computed by the verifier from public data only.
            rebuilt = self._rebuilt(attempt.response, attempt.challenge)
            np.testing.assert_array_equal(rebuilt, attempt.shifted)
            np.testing.assert_array_equal(rebuilt, (attempt.commitment - shift) % QP)
            self.assertFalse(np.array_equal(rebuilt, attempt.commitment))
            np.testing.assert_array_equal(
                decomposition.high_bits(rebuilt, alpha, QP), attempt.high
            )
            self.assertTrue(
                self._verify(challenge, self._token(challenge, attempt.response, attempt.seed))
            )

    def test_prover_output_satisfies_both_conditions_and_verifies(self) -> None:
        gamma1, gamma2, beta = (self.parameters[name] for name in ("gamma1", "gamma2", "beta"))
        for _ in range(20):
            challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
            response, seed, challenge_polynomial = self._proof(challenge)
            self.assertLess(int(np.abs(response).max()), gamma1 - beta)
            low = decomposition.low_bits(
                self._rebuilt(response, challenge_polynomial), 2 * gamma2, QP
            )
            self.assertLess(int(np.abs(low).max()), gamma2 - beta)
            self.assertEqual(len(seed), 32)
            self.assertTrue(self._verify(challenge, self._token(challenge, response, seed)))

    def test_forged_proofs_are_rejected(self) -> None:
        box = self.parameters["gamma1"] - self.parameters["beta"] - 1
        shape = (self.rank, D)

        def flipped(seed):
            return bytes([seed[0] ^ 1]) + seed[1:]

        forgeries = {
            "modified response": lambda z, seed: (_nudge(z), seed),
            "modified challenge seed": lambda z, seed: (z, flipped(seed)),
            "negated response": lambda z, seed: (-z, seed),
            "zero response": lambda z, seed: (np.zeros_like(z), seed),
            "random response in the box": lambda z, seed: (
                sampling.sample_uniform_box(shape, box), seed
            ),
            "random response and seed": lambda z, seed: (
                sampling.sample_uniform_box(shape, box), secrets.token_bytes(32)
            ),
            "short response": lambda z, seed: (
                sampling.sample_centered_binomial(shape, ETA), seed
            ),
        }
        for label, forge in forgeries.items():
            with self.subTest(forgery=label):
                challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
                response, seed, _ = self._proof(challenge)
                self.assertFalse(
                    self._verify(challenge, self._token(challenge, *forge(response, seed)))
                )

    def test_guessing_the_secret_does_not_authenticate(self) -> None:
        # A prover that runs the honest algorithm with fresh CBD vectors instead of (s, e).
        context = self.protocol._context(self.system_parameters)
        guess = {
            "s": codec.encode_packed(
                sampling.sample_centered_binomial((self.rank, D), ETA) + ETA, 2 * ETA + 1
            ),
            "e": codec.encode_packed(
                sampling.sample_centered_binomial((self.rank, D), ETA) + ETA, 2 * ETA + 1
            ),
            "public_key_digest": codec.encode_bytes(
                self.protocol._public_vector(context, self.public_key)[0]
            ),
        }
        for _ in range(5):
            self.assertFalse(self._verify(*self._authenticate(private_key=guess)))

    # -- token hiding ------------------------------------------------------------

    def test_token_is_opaque_and_has_the_expected_size(self) -> None:
        challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        response, seed, _ = self._proof(challenge)
        token = self._token(challenge, response, seed)
        tok1, tok2 = base64.b64decode(token["tok1"]), base64.b64decode(token["tok2"])
        self.assertEqual(len(tok1), 1088)
        # z at 18 bits per coefficient, c~, ticket, nu; no commitment.
        self.assertEqual(len(tok2), 12 + (2304 + 32 + 32 + 8) + 16)
        self.assertEqual(len(tok1) + len(tok2), 3492)

        wire = tok1 + tok2
        for secret_part in (
            codec.pack_coefficients(response + GAMMA1, 2 * GAMMA1),
            seed,
            base64.b64decode(challenge["ticket"]),
        ):
            self.assertNotIn(secret_part, wire)
            self.assertNotIn(secret_part[:16], wire)
        # Sanity only, not a proof of indistinguishability: the ciphertext bits are balanced.
        ones = np.unpackbits(np.frombuffer(tok2, dtype=np.uint8)).mean()
        self.assertAlmostEqual(float(ones), 0.5, delta=0.03)
        # Sealing the same proof twice gives unrelated tokens.
        again = self._token(challenge, response, seed)
        self.assertNotEqual(token["tok1"], again["tok1"])
        self.assertNotEqual(token["tok2"], again["tok2"])

    def test_only_the_designated_verifier_can_open_the_token(self) -> None:
        challenge, response = self._authenticate()
        other_deployment = self.protocol.generate_system_parameters(**self.parameters)
        self.assertFalse(
            self.protocol.verify_response(other_deployment, self.public_key, challenge, response)
        )
        self.assertTrue(self._verify(challenge, response))

    def test_any_modification_of_the_token_is_rejected(self) -> None:
        for part in ("tok1", "tok2"):
            with self.subTest(part=part):
                challenge, response = self._authenticate()
                tampered = dict(response, **{part: _flip_first_byte(response[part])})
                self.assertFalse(self._verify(challenge, tampered))

    def test_authentic_token_with_a_response_outside_the_bound_is_rejected(self) -> None:
        context = self.protocol._context(self.system_parameters)
        challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        ticket, nu = self.protocol._parse_challenge(challenge)
        # Every coefficient decodes to gamma1 - 1, which is above gamma1 - beta.
        payload = b"\xff" * 2304 + bytes(32) + ticket + nu.to_bytes(8, "big")
        self.assertEqual(len(payload), context.payload_bytes)
        tok1, tok2 = token_hiding.seal(
            context.verifier_public_key,
            payload,
            self.protocol._token_associated_data(context),
        )
        token = {"tok1": codec.encode_bytes(tok1), "tok2": codec.encode_bytes(tok2)}
        self.assertFalse(self._verify(challenge, token))

    # -- verifier custody --------------------------------------------------------

    def test_system_parameters_hold_only_public_material(self) -> None:
        self.assertEqual(set(self.system_parameters), {"protocol", "parameters", "rho", "vpk"})
        self.assertEqual(len(base64.b64decode(self.system_parameters["rho"])), 32)
        self.assertEqual(len(base64.b64decode(self.system_parameters["vpk"])), 1184)
        self.assertEqual(self.system_parameters["parameters"], self.parameters)

    def test_verification_needs_the_process_that_holds_the_verifier_key(self) -> None:
        challenge, response = self._authenticate()
        foreign_public_key, _ = token_hiding.generate_verifier_keypair()
        foreign = dict(self.system_parameters, vpk=codec.encode_bytes(foreign_public_key))
        with self.assertRaises(InvalidProtocolDataError):
            self.protocol.verify_response(foreign, self.public_key, challenge, response)

    def test_setup_generates_fresh_seed_and_verifier_key(self) -> None:
        other = self.protocol.generate_system_parameters(**self.parameters)
        self.assertNotEqual(other["rho"], self.system_parameters["rho"])
        self.assertNotEqual(other["vpk"], self.system_parameters["vpk"])

    # -- serialization and sizes -------------------------------------------------

    def test_artifacts_survive_a_json_round_trip_without_loss(self) -> None:
        challenge, response = self._authenticate()
        artifacts = [self.system_parameters, self.public_key, self.private_key, challenge, response]
        restored = [json.loads(canonical_json_bytes(artifact).decode("utf-8")) for artifact in artifacts]
        self.assertEqual(restored, artifacts)
        system_parameters, public_key, private_key, challenge, response = restored
        self.assertTrue(
            self.protocol.verify_response(system_parameters, public_key, challenge, response)
        )
        second_challenge = self.protocol.generate_challenge(system_parameters, public_key)
        self.assertTrue(
            self.protocol.verify_response(
                system_parameters,
                public_key,
                second_challenge,
                self.protocol.solve_challenge(system_parameters, private_key, second_challenge),
            )
        )

    def test_key_sizes(self) -> None:
        # t at 23 bits per coefficient; s and e at 3 bits (values eta + coefficient).
        self.assertEqual(len(base64.b64decode(self.public_key["t"])), 4 * 256 * 23 // 8)
        self.assertEqual(len(base64.b64decode(self.public_key["t"])), 2944)
        self.assertEqual(len(base64.b64decode(self.private_key["s"])), 384)
        self.assertEqual(len(base64.b64decode(self.private_key["e"])), 384)
        self.assertEqual(set(self.private_key), {"s", "e", "public_key_digest"})
        self.assertEqual(set(self.public_key), {"t"})

    # -- malformed inputs --------------------------------------------------------

    def test_malformed_tokens_are_reported_as_invalid_data(self) -> None:
        challenge, response = self._authenticate()
        for malformed in (
            {"tok1": response["tok1"]},
            dict(response, tok1="not-base64!"),
            dict(response, tok1=response["tok1"][:-4]),
            dict(response, tok2=response["tok2"][:-4]),
            "not-a-mapping",
        ):
            with self.subTest(malformed=str(malformed)[:30]):
                with self.assertRaises(InvalidProtocolDataError):
                    self._verify(challenge, malformed)

    def test_malformed_keys_challenges_and_parameters_are_rejected(self) -> None:
        challenge, response = self._authenticate()
        out_of_range = bytearray(base64.b64decode(self.public_key["t"]))
        out_of_range[0], out_of_range[1], out_of_range[2] = 0xFF, 0xFF, 0x7F
        with self.assertRaises(InvalidProtocolDataError):
            self._verify(challenge, response, {"t": codec.encode_bytes(bytes(out_of_range))})
        with self.assertRaises(InvalidProtocolDataError):
            self._verify(challenge, response, {"t": "AAAA"})
        for bad_challenge in (
            {"ticket": challenge["ticket"]},
            {"ticket": "AAAA", "nu": challenge["nu"]},
            {"ticket": challenge["ticket"], "nu": -1},
            {"ticket": challenge["ticket"], "nu": "1"},
            {"ticket": challenge["ticket"], "nu": True},
        ):
            with self.subTest(challenge=str(bad_challenge)[-30:]):
                with self.assertRaises(InvalidProtocolDataError):
                    self.protocol.solve_challenge(self.system_parameters, self.private_key, bad_challenge)
        for bad_system in (
            dict(self.system_parameters, protocol="ring_lwe"),
            {k: v for k, v in self.system_parameters.items() if k != "vpk"},
            dict(self.system_parameters, rho="AAAA"),
            dict(self.system_parameters, parameters={"q": 3329}),
        ):
            with self.subTest(system=str(sorted(bad_system))):
                with self.assertRaises(InvalidProtocolDataError):
                    self.protocol.generate_challenge(bad_system, self.public_key)

    def test_private_key_outside_the_cbd_range_is_rejected(self) -> None:
        challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        too_large = np.full((self.rank, D), ETA, dtype=np.int64)
        too_large[0, 0] = 2 * ETA + 1  # encodes the coefficient eta + 1
        outside = codec.encode_bytes(codec.pack_coefficients(too_large, 8))
        for private_key in (
            dict(self.private_key, s=outside),
            dict(self.private_key, e=outside),
            dict(self.private_key, s=self.private_key["s"][:-4]),
            dict(self.private_key, public_key_digest="AAAA"),
            {"s": self.private_key["s"], "public_key_digest": self.private_key["public_key_digest"]},
            {"s": self.private_key["s"], "e": self.private_key["e"]},
        ):
            with self.subTest(private_key=sorted(private_key)):
                with self.assertRaises(InvalidProtocolDataError):
                    self.protocol.solve_challenge(self.system_parameters, private_key, challenge)

    def test_enrollment_must_use_the_setup_parameters(self) -> None:
        with self.assertRaises(InvalidProtocolDataError):
            self.protocol.generate_keypair(
                self.system_parameters,
                **self.protocol.resolve_parameters({"gamma1": 1 << 18}),
            )

    # -- contract ----------------------------------------------------------------

    def test_common_conformance_gate_passes_unmodified(self) -> None:
        protocol = ProposedLWEAuthProtocol()
        checks = run_conformance_checks(protocol, protocol.resolve_parameters())
        self.assertTrue(all(checks.values()))

    def test_operations_do_not_mutate_their_inputs(self) -> None:
        originals = copy.deepcopy((self.system_parameters, self.public_key, self.private_key))
        challenge, response = self._authenticate()
        snapshot = copy.deepcopy((challenge, response))
        self._verify(challenge, response)
        self.assertEqual((self.system_parameters, self.public_key, self.private_key), originals)
        self.assertEqual((challenge, response), snapshot)


class RejectionSamplingTests(_Deployment):
    """Both abort conditions, their rates, and what each one protects."""

    def test_both_abort_branches_are_taken_at_the_predicted_rates(self) -> None:
        gamma1, gamma2, beta = (self.parameters[name] for name in ("gamma1", "gamma2", "beta"))
        coefficients = self.rank * D
        response_rate = ((2 * (gamma1 - beta) - 1) / (2 * gamma1 - 1)) ** coefficients
        low_rate = ((2 * (gamma2 - beta) - 1) / (2 * gamma2)) ** coefficients
        proofs = 300
        with mock.patch.object(
            proposed_lwe.sampling, "sample_uniform_box", wraps=sampling.sample_uniform_box
        ) as masks, mock.patch.object(
            proposed_lwe.decomposition, "low_bits", wraps=decomposition.low_bits
        ) as low_checks:
            for _ in range(proofs):
                challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
                self._proof(challenge)
        attempts, reached_low_check = masks.call_count, low_checks.call_count
        self.assertGreater(attempts, reached_low_check)       # some responses were too large
        self.assertGreater(reached_low_check, proofs)         # some low parts left no room
        self.assertAlmostEqual(reached_low_check / attempts, response_rate, delta=0.10)
        self.assertAlmostEqual(proofs / reached_low_check, low_rate, delta=0.12)
        self.assertAlmostEqual(
            response_rate * low_rate,
            proposed_lwe.acceptance_probability(self.rank, gamma1, gamma2, beta),
            places=12,
        )

    def test_verifier_rejects_a_valid_hash_whose_response_is_too_large(self) -> None:
        # An attempt the honest prover discards for ||z||_inf alone: its hash is right,
        # so only the verifier's norm check stands between it and acceptance.
        challenge, attempt = self._attempt_where(
            lambda attempt: not attempt.response_ok and attempt.low_ok and attempt.encodable
        )
        token = self._token(challenge, attempt.response, attempt.seed)
        self.assertFalse(self._verify(challenge, token))
        self._forget_spent_tickets()
        with mock.patch.object(
            proposed_lwe._Context,
            "response_bound",
            new_callable=mock.PropertyMock,
            return_value=QP,
        ):
            self.assertTrue(self._verify(challenge, token))

    def test_verifier_rejects_a_response_exactly_on_the_bound(self) -> None:
        challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        response, seed, _ = self._proof(challenge)
        on_the_bound = response.copy()
        on_the_bound[0, 0] = self.parameters["gamma1"] - self.parameters["beta"]
        self.assertFalse(self._verify(challenge, self._token(challenge, on_the_bound, seed)))

    def test_low_bits_condition_is_what_makes_every_released_proof_verify(self) -> None:
        # An attempt with a short response whose low part left no room and whose high
        # bits did change when c e was subtracted: released as is, it would be an
        # honest proof the verifier rejects.
        alpha = 2 * self.parameters["gamma2"]
        challenge, attempt = self._attempt_where(
            lambda attempt: attempt.response_ok
            and not attempt.low_ok
            and not np.array_equal(
                decomposition.high_bits(attempt.shifted, alpha, QP), attempt.high
            )
        )
        self.assertFalse(
            self._verify(challenge, self._token(challenge, attempt.response, attempt.seed))
        )

    def test_prover_gives_up_after_the_attempt_limit(self) -> None:
        # A mask on the edge of its box always gives ||z||_inf >= gamma1 - beta.
        gamma1 = self.parameters["gamma1"]
        challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        edge = np.full((self.rank, D), gamma1 - 1, dtype=np.int64)
        with mock.patch.object(proposed_lwe, "MAX_PROOF_ATTEMPTS", 5), mock.patch.object(
            proposed_lwe.sampling, "sample_uniform_box", return_value=edge
        ) as masks:
            with self.assertRaises(CryptoCoreError):
                self.protocol.solve_challenge(self.system_parameters, self.private_key, challenge)
        self.assertEqual(masks.call_count, 5)


class NarrowMaskTests(_Deployment):
    """gamma1 = 2^14 at rank 3: about one attempt in thirteen is released, and all of them verify."""

    overrides = {"gamma1": 1 << 14, "k_proof": 3}

    def test_honest_acceptance_stays_total_when_most_attempts_abort(self) -> None:
        self.assertLess(
            proposed_lwe.acceptance_probability(
                self.rank, self.parameters["gamma1"], self.parameters["gamma2"], self.parameters["beta"]
            ),
            0.09,
        )
        with mock.patch.object(
            proposed_lwe.sampling, "sample_uniform_box", wraps=sampling.sample_uniform_box
        ) as masks:
            for _ in range(20):
                self.assertTrue(self._verify(*self._authenticate()))
        self.assertGreater(masks.call_count / 20, 4)

    def test_response_uses_fifteen_bits_per_coefficient(self) -> None:
        _, response = self._authenticate()
        self.assertEqual(len(base64.b64decode(response["tok2"])), 12 + (1440 + 72) + 16)


class NonPowerOfTwoMaskTests(_Deployment):
    """gamma1 = 100000: some 18-bit patterns are not encodings of any response."""

    overrides = {"gamma1": 100_000}

    def test_honest_authentication(self) -> None:
        for _ in range(10):
            self.assertTrue(self._verify(*self._authenticate()))

    def test_authentic_token_with_an_undecodable_response_is_rejected(self) -> None:
        context = self.protocol._context(self.system_parameters)
        challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        ticket, nu = self.protocol._parse_challenge(challenge)
        payload = b"\xff" * context.response_bytes + bytes(32) + ticket + nu.to_bytes(8, "big")
        tok1, tok2 = token_hiding.seal(
            context.verifier_public_key,
            payload,
            self.protocol._token_associated_data(context),
        )
        token = {"tok1": codec.encode_bytes(tok1), "tok2": codec.encode_bytes(tok2)}
        self.assertFalse(self._verify(challenge, token))


class ProofRankThreeTests(_Deployment):
    """The proof layer at the manuscript's rank 3 (dimension 768); transport layer unchanged."""

    overrides = {"k_proof": 3}

    def test_honest_authentication_and_session_key(self) -> None:
        for _ in range(20):
            self.assertTrue(self._verify(*self._authenticate()))
        challenge, response = self._authenticate()
        self.assertTrue(self._verify(challenge, response))
        client_share, client_secret = self.protocol.generate_key_agreement_share(
            self.system_parameters, "client"
        )
        server_share, server_secret = self.protocol.generate_key_agreement_share(
            self.system_parameters, "server"
        )
        hint, server_key = self.protocol.generate_reconciliation_hint(
            self.system_parameters, challenge, client_share, server_secret
        )
        self.assertEqual(
            self.protocol.reconcile_session_key(
                self.system_parameters, server_share, client_secret, hint
            ),
            server_key,
        )
        # The key agreement stays at the manuscript's rank and modulus.
        self.assertEqual(len(base64.b64decode(client_share["b"])), 1152)

    def test_sizes_shrink_with_the_rank(self) -> None:
        _, response = self._authenticate()
        self.assertEqual(len(base64.b64decode(self.public_key["t"])), 2208)
        self.assertEqual(len(base64.b64decode(self.private_key["s"])), 288)
        self.assertEqual(
            len(base64.b64decode(response["tok1"])) + len(base64.b64decode(response["tok2"])),
            1088 + 12 + (1728 + 72) + 16,
        )

    def test_forgeries_and_keys_of_another_rank_are_rejected(self) -> None:
        challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        response, seed, _ = self._proof(challenge)
        self.assertFalse(self._verify(challenge, self._token(challenge, _nudge(response), seed)))
        default_rank = ProposedLWEAuthProtocol(clock=self.clock)
        parameters = default_rank.resolve_parameters()
        other_public, other_private = default_rank.generate_keypair(
            default_rank.generate_system_parameters(**parameters), **parameters
        )
        challenge, response = self._authenticate()
        with self.assertRaises(InvalidProtocolDataError):
            self._verify(challenge, response, other_public)
        with self.assertRaises(InvalidProtocolDataError):
            self._authenticate(private_key=other_private)

    def test_common_conformance_gate_passes_unmodified(self) -> None:
        protocol = ProposedLWEAuthProtocol()
        checks = run_conformance_checks(protocol, protocol.resolve_parameters(self.overrides))
        self.assertTrue(all(checks.values()))


class SessionKeyAgreementTests(_Deployment):
    def _authenticated_challenge(self):
        challenge, response = self._authenticate()
        self.assertTrue(self._verify(challenge, response))
        return challenge

    def _shares(self):
        client = self.protocol.generate_key_agreement_share(self.system_parameters, "client")
        server = self.protocol.generate_key_agreement_share(self.system_parameters, "server")
        return client, server

    def test_both_sides_agree_over_many_sessions(self) -> None:
        keys = set()
        for _ in range(30):
            challenge = self._authenticated_challenge()
            (client_share, client_secret), (server_share, server_secret) = self._shares()
            hint, server_key = self.protocol.generate_reconciliation_hint(
                self.system_parameters, challenge, client_share, server_secret
            )
            self.assertEqual(
                self.protocol.reconcile_session_key(
                    self.system_parameters, server_share, client_secret, hint
                ),
                server_key,
            )
            keys.add(server_key)
        self.assertEqual(len(keys), 30)

    def test_shares_live_in_the_transport_modulus(self) -> None:
        (client_share, client_secret), (server_share, _) = self._shares()
        for share in (client_share, server_share):
            raw = base64.b64decode(share["b"])
            self.assertEqual(len(raw), K * D * 12 // 8)
            self.assertLess(int(codec.unpack_coefficients(raw, "b", (K, D), Q).max()), Q)
        self.assertEqual(len(base64.b64decode(client_secret["s"])), 1152)

    def test_hint_is_exactly_32_bytes_and_serializable(self) -> None:
        challenge = self._authenticated_challenge()
        (client_share, _), (_, server_secret) = self._shares()
        hint, server_key = self.protocol.generate_reconciliation_hint(
            self.system_parameters, challenge, client_share, server_secret
        )
        self.assertEqual(set(hint), {"v"})
        self.assertEqual(len(base64.b64decode(hint["v"])), 32)
        self.assertEqual(len(server_key), 32)
        self.assertEqual(json.loads(canonical_json_bytes(hint).decode("utf-8")), hint)

    def test_hint_requires_a_successful_authentication(self) -> None:
        (client_share, _), (_, server_secret) = self._shares()
        unverified, _ = self._authenticate()
        with self.assertRaises(InvalidProtocolDataError):
            self.protocol.generate_reconciliation_hint(
                self.system_parameters, unverified, client_share, server_secret
            )
        _, other_private = self.protocol.generate_keypair(self.system_parameters, **self.parameters)
        rejected, response = self._authenticate(private_key=other_private)
        self.assertFalse(self._verify(rejected, response))
        with self.assertRaises(InvalidProtocolDataError):
            self.protocol.generate_reconciliation_hint(
                self.system_parameters, rejected, client_share, server_secret
            )

    def test_hint_is_issued_once_per_authentication(self) -> None:
        challenge = self._authenticated_challenge()
        (client_share, _), (_, server_secret) = self._shares()
        self.protocol.generate_reconciliation_hint(
            self.system_parameters, challenge, client_share, server_secret
        )
        with self.assertRaises(InvalidProtocolDataError):
            self.protocol.generate_reconciliation_hint(
                self.system_parameters, challenge, client_share, server_secret
            )

    def test_another_client_secret_does_not_derive_the_session_key(self) -> None:
        challenge = self._authenticated_challenge()
        (client_share, _), (server_share, server_secret) = self._shares()
        _, unrelated_secret = self.protocol.generate_key_agreement_share(
            self.system_parameters, "client"
        )
        hint, server_key = self.protocol.generate_reconciliation_hint(
            self.system_parameters, challenge, client_share, server_secret
        )
        self.assertNotEqual(
            self.protocol.reconcile_session_key(
                self.system_parameters, server_share, unrelated_secret, hint
            ),
            server_key,
        )

    def test_noise_between_both_sides_is_far_below_the_reconciliation_bound(self) -> None:
        largest = 0
        for _ in range(20):
            (client_share, client_secret), (server_share, server_secret) = self._shares()
            client_value = module.inner_product(
                self.protocol._share(server_share, "la cuota del servidor"),
                self.protocol._small_vector(client_secret, "el secreto del cliente"),
                Q,
            )
            server_value = module.inner_product(
                self.protocol._share(client_share, "la cuota del cliente"),
                self.protocol._small_vector(server_secret, "el secreto del servidor"),
                Q,
            )
            largest = max(largest, int(np.abs(module.centered(server_value - client_value, Q)).max()))
        # Standard deviation about sqrt(2 * k * d) = 39; the bound is 415 minus the fresh e_S.
        self.assertLess(largest, 300)

    def test_malformed_shares_secrets_and_hints_are_rejected(self) -> None:
        challenge = self._authenticated_challenge()
        (client_share, client_secret), (server_share, server_secret) = self._shares()
        with self.assertRaises(InvalidProtocolDataError):
            self.protocol.generate_key_agreement_share(self.system_parameters, "relay")
        with self.assertRaises(InvalidProtocolDataError):
            self.protocol.generate_reconciliation_hint(
                self.system_parameters, challenge, {"b": "AAAA"}, server_secret
            )
        # A rejected request must not consume the pending hint.
        hint, server_key = self.protocol.generate_reconciliation_hint(
            self.system_parameters, challenge, client_share, server_secret
        )
        for bad_hint in ({"v": "AAAA"}, {}, "not-a-mapping"):
            with self.subTest(hint=str(bad_hint)):
                with self.assertRaises(InvalidProtocolDataError):
                    self.protocol.reconcile_session_key(
                        self.system_parameters, server_share, client_secret, bad_hint
                    )
        self.assertEqual(
            self.protocol.reconcile_session_key(
                self.system_parameters, server_share, client_secret, hint
            ),
            server_key,
        )


class ManuscriptDeviationTests(_Deployment):
    """Executable evidence for the points where the code departs from the manuscript.

    The manuscript writes its proof over q = 3329, so these tests use that modulus.
    """

    def _instance(self):
        context = self.protocol._context(self.system_parameters)
        matrix = self.protocol._agreement_matrix(context)
        secret = sampling.sample_centered_binomial((K, D), ETA)
        error = sampling.sample_centered_binomial((K, D), ETA)
        mask = sampling.sample_centered_binomial((K, D), ETA)
        public_vector = (module.matrix_vector(matrix, secret, Q) + error) % Q
        commitment = module.matrix_vector(matrix, mask, Q)
        return matrix, secret, error, mask, public_vector, commitment

    def test_matrix_challenge_breaks_the_cancellation_the_manuscript_relies_on(self) -> None:
        # tex:186-192 needs A (s L) = (A s) L. For L in R_q^{k x k} that requires A L = L A.
        matrix, secret, _, mask, public_vector, commitment = self._instance()
        uniform = sampling.sample_uniform_mod_q((K, K, D), Q)
        short = np.stack(
            [
                np.stack([sampling.derive_sparse_ternary(bytes([i, j]), D, 8) for j in range(K)])
                for i in range(K)
            ]
        )
        for label, challenge_matrix in (("uniform", uniform), ("short", short)):
            for orientation, oriented in (
                ("L s", challenge_matrix),
                ("L^T s", module.transpose(challenge_matrix)),
            ):
                with self.subTest(challenge=label, product=orientation):
                    response = (module.matrix_vector(oriented, secret, Q) + mask) % Q
                    residual = module.centered(
                        module.matrix_vector(matrix, response, Q)
                        - module.matrix_vector(oriented, public_vector, Q)
                        - commitment,
                        Q,
                    )
                    # An honest proof is rejected by any bound that excludes something.
                    self.assertGreater(int(np.abs(residual).max()), Q // 4)

    def test_scalar_short_challenge_makes_the_manuscript_derivation_hold(self) -> None:
        matrix, secret, error, mask, public_vector, commitment = self._instance()
        challenge = sampling.derive_sparse_ternary(b"challenge", D, self.parameters["kappa"])
        response = module.centered(module.scale_vector(challenge, secret, Q), Q) + mask
        residual = module.centered(
            module.matrix_vector(matrix, response, Q)
            - module.scale_vector(challenge, public_vector, Q)
            - commitment,
            Q,
        )
        np.testing.assert_array_equal(
            residual, module.centered(-module.scale_vector(challenge, error, Q), Q)
        )
        # beta = eta * kappa bounds c e and c s: the quantity both rejections are built on.
        self.assertLessEqual(int(np.abs(residual).max()), self.parameters["beta"])
        self.assertLessEqual(
            int(np.abs(module.centered(module.scale_vector(challenge, secret, Q), Q)).max()),
            self.parameters["beta"],
        )

    def test_uniform_scalar_challenge_would_make_both_bounds_vacuous(self) -> None:
        matrix, secret, error, mask, _, _ = self._instance()
        challenge = sampling.sample_uniform_mod_q((D,), Q)
        response = module.centered(module.scale_vector(challenge, secret, Q) + mask, Q)
        residual = module.centered(module.scale_vector(challenge, error, Q), Q)
        self.assertGreater(int(np.abs(response).max()), Q // 4)
        self.assertGreater(int(np.abs(residual).max()), Q // 4)

    def test_commitment_in_the_token_would_give_the_verifier_the_key(self) -> None:
        # tex:112 seals w with z and tex:196 checks A z - t L - w, which is exactly -c e.
        # Dividing by c gives e, and then s = A^-1 (t - e): one token, whole key.
        matrix, secret, error, mask, public_vector, commitment = self._instance()
        matrix_inverse = _matrix_inverse(matrix)
        if matrix_inverse is None:
            self.skipTest("the expanded matrix is not invertible (probability about 4e-5)")
        for index in range(8):
            challenge = sampling.derive_sparse_ternary(bytes([index]), D, self.parameters["kappa"])
            challenge_inverse = _ring_inverse(challenge)
            if challenge_inverse is not None:
                break
        else:
            self.fail("no invertible challenge in 8 attempts")
        response = module.centered(module.scale_vector(challenge, secret, Q), Q) + mask
        residual = module.centered(
            module.matrix_vector(matrix, response, Q)
            - module.scale_vector(challenge, public_vector, Q)
            - commitment,
            Q,
        )
        recovered_error = module.centered(-module.scale_vector(challenge_inverse, residual, Q), Q)
        np.testing.assert_array_equal(recovered_error, error)
        np.testing.assert_array_equal(
            module.centered(module.matrix_vector(matrix_inverse, public_vector - recovered_error, Q), Q),
            secret,
        )
        # The commitment alone also gives the mask, because A is square: y = A^-1 w.
        np.testing.assert_array_equal(
            module.centered(module.matrix_vector(matrix_inverse, commitment, Q), Q), mask
        )

    def test_manuscript_mask_does_not_hide_the_secret_even_without_the_commitment(self) -> None:
        # tex:66-69 samples the mask from CBD(eta). Then z = c s + y is a linear system in
        # s whose noise is bounded by eta: least squares over ten responses solves it.
        secret = sampling.sample_centered_binomial((K, D), ETA)
        pairs = []
        for index in range(10):
            challenge = sampling.derive_sparse_ternary(bytes([index]), D, self.parameters["kappa"])
            mask = sampling.sample_centered_binomial((K, D), ETA)
            pairs.append(
                (challenge, module.centered(module.scale_vector(challenge, secret, Q), Q) + mask)
            )
        recovered = np.clip(np.rint(_least_squares_estimate(pairs)), -ETA, ETA).astype(np.int64)
        np.testing.assert_array_equal(recovered, secret)

    def test_printed_reconciliation_formula_tolerates_no_error(self) -> None:
        # tex:241: rec(w_A, v) = round((2 / q) (w_A - (2 v + 1) q / 4)) mod 2.
        hints = np.array([0, 1])[None, :]
        printed = ((4 * RESIDUES[:, None] - (2 * hints + 1) * Q + Q) // (2 * Q)) % 2

        def printed_rec(values, hint):
            return ((2 * (values % Q)) // Q - hint) % 2

        for hint_value in (0, 1):
            np.testing.assert_array_equal(printed[:, hint_value], printed_rec(RESIDUES, hint_value))

        key = reconciliation.modular_round(RESIDUES, Q)
        hint = reconciliation.cross_round(RESIDUES, Q)
        np.testing.assert_array_equal(printed_rec(RESIDUES, hint), key)
        self.assertFalse(np.array_equal(printed_rec(RESIDUES + 1, hint), key))

        rng = np.random.default_rng(4)
        server_values = rng.integers(0, Q, size=(500, D))
        noise = np.rint(rng.normal(0, 39.2, size=(500, D))).astype(np.int64)
        expected = reconciliation.modular_round(server_values, Q)
        server_hint = reconciliation.cross_round(server_values, Q)
        printed_failures = (printed_rec(server_values + noise, server_hint) != expected).any(axis=1)
        implemented_failures = (
            reconciliation.reconcile((server_values + noise) % Q, server_hint, Q) != expected
        ).any(axis=1)
        self.assertGreater(float(printed_failures.mean()), 0.9)
        self.assertEqual(int(implemented_failures.sum()), 0)

    def test_quadrant_table_contradicts_the_rounding_formula(self) -> None:
        # tex:219-224 assigns key bit 0 to [0, q/2) and 1 to [q/2, q); tex:231 rounds.
        table_bit = (RESIDUES >= Q // 2).astype(int)
        formula_bit = reconciliation.modular_round(RESIDUES, Q)
        self.assertGreater(int((table_bit != formula_bit).sum()), Q // 3)

    def test_encapsulated_key_replaces_the_client_chosen_key(self) -> None:
        public_key, _ = token_hiding.generate_verifier_keypair()
        verifier_key = token_hiding.mlkem.MLKEM768PublicKey.from_public_bytes(public_key)
        self.assertFalse(any("encrypt" in name.lower() for name in dir(verifier_key)))
        shared_secret, ciphertext = verifier_key.encapsulate()
        self.assertEqual((len(shared_secret), len(ciphertext)), (32, 1088))


class DualModulusRationaleTests(unittest.TestCase):
    """Why the proof needs its own modulus, in numbers."""

    beta = ETA * proposed_lwe.DEFAULT_KAPPA
    coefficients = K * D

    def _low_bits_acceptance(self, modulus: int) -> dict[int, float]:
        """Per-attempt probability of the low-bits condition for every usable rounding step.

        The step alpha = 2 gamma2 must divide modulus - 1 and leave at least two
        high values; each coefficient passes with probability
        (2 (gamma2 - beta) - 1) / alpha and all k d must pass.
        """
        acceptance = {}
        for high_values in range(2, (modulus - 1) // (2 * (self.beta + 1)) + 1):
            if (modulus - 1) % (2 * high_values):
                continue
            half_step = (modulus - 1) // (2 * high_values)
            acceptance[2 * half_step] = (
                (2 * (half_step - self.beta) - 1) / (2 * half_step)
            ) ** self.coefficients
        return acceptance

    def test_manuscript_modulus_has_no_usable_rounding_step(self) -> None:
        acceptance = self._low_bits_acceptance(Q)
        self.assertEqual(sorted(acceptance), [104, 128, 208, 256, 416, 832, 1664])
        self.assertLess(max(acceptance.values()), 1e-15)

    def test_manuscript_modulus_cannot_hold_a_mask_that_hides_the_secret(self) -> None:
        # Smallest gamma1 whose response condition alone passes one attempt in ten,
        # against the largest centered value of Z_q.
        gamma1 = next(
            gamma
            for gamma in range(self.beta + 1, 1 << 20)
            if ((2 * (gamma - self.beta) - 1) / (2 * gamma - 1)) ** self.coefficients >= 0.1
        )
        self.assertGreater(gamma1, 8 * (Q // 2))
        self.assertLess(8 * gamma1, QP)

    def test_proof_modulus_has_the_rounding_steps_of_ml_dsa(self) -> None:
        acceptance = self._low_bits_acceptance(QP)
        self.assertIn(2 * GAMMA2, acceptance)
        self.assertIn(2 * ((QP - 1) // 32), acceptance)
        self.assertAlmostEqual(acceptance[2 * GAMMA2], 0.687, delta=0.001)
        self.assertGreater(
            proposed_lwe.acceptance_probability(K, GAMMA1, GAMMA2, self.beta), 0.5
        )


class ZeroKnowledgeEvidenceTests(_Deployment):
    """What the designated verifier holds after decrypting, and what it can do with it.

    These tests are evidence for the security assessment, not a proof. They must
    be revised, not deleted, if the proof construction changes.
    """

    def test_token_carries_the_response_and_the_challenge_seed_never_the_commitment(self) -> None:
        context = self.protocol._context(self.system_parameters)
        self.assertEqual(context.response_bytes, self.rank * D * 18 // 8)
        self.assertEqual(context.payload_bytes, context.response_bytes + 32 + 32 + 8)
        # A commitment in R_q'^k would need 23 bits per coefficient on its own.
        self.assertLess(context.payload_bytes, codec.packed_length(self.rank * D, QP))

    def test_transcript_simulated_without_the_secret_passes_every_verifier_check(self) -> None:
        # The simulator of the zero-knowledge argument, run for real: it uses A', t and
        # the ticket, never s or e. With the random oracle programmed at one point the
        # verifier accepts its output, so an accepted (z, c~) is something the verifier
        # could have produced alone.
        context, matrix, _, _, _, _ = self._internals()
        public_vector = self._public_vector()
        gamma2, beta = self.parameters["gamma2"], self.parameters["beta"]
        challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        ticket, nu = self.protocol._parse_challenge(challenge)
        for _ in range(500):
            seed = secrets.token_bytes(32)
            challenge_polynomial = self.protocol._challenge_polynomial(context, seed)
            response = sampling.sample_uniform_box((self.rank, D), context.response_bound - 1)
            rebuilt = (
                module.matrix_vector(matrix, response, QP)
                - module.scale_vector(challenge_polynomial, public_vector, QP)
            )
            high, low = decomposition.decompose(rebuilt, context.rounding_step, QP)
            if int(np.abs(low).max()) < gamma2 - beta:
                break
        else:
            self.fail("the simulator did not finish in 500 attempts")
        token = self._token(challenge, response, seed)

        # With the real hash it is rejected: simulating is not forging.
        self.assertFalse(self._verify(challenge, token))
        self._forget_spent_tickets()

        real_hash = ProposedLWEAuthProtocol._challenge_seed

        def programmed(hash_context, matrix_digest, public_key_digest, high_bits, hash_ticket, hash_nu):
            if np.array_equal(high_bits, high) and (hash_ticket, hash_nu) == (ticket, nu):
                return seed
            return real_hash(
                hash_context, matrix_digest, public_key_digest, high_bits, hash_ticket, hash_nu
            )

        with mock.patch.object(
            ProposedLWEAuthProtocol, "_challenge_seed", staticmethod(programmed)
        ):
            self.assertTrue(self._verify(challenge, token))

    def test_simulator_and_prover_pass_the_low_bits_condition_at_the_same_rate(self) -> None:
        context, matrix, _, _, _, _ = self._internals()
        public_vector = self._public_vector()
        gamma2, beta = self.parameters["gamma2"], self.parameters["beta"]
        trials = 400
        simulated = 0
        for _ in range(trials):
            challenge_polynomial = self.protocol._challenge_polynomial(
                context, secrets.token_bytes(32)
            )
            response = sampling.sample_uniform_box((self.rank, D), context.response_bound - 1)
            rebuilt = (
                module.matrix_vector(matrix, response, QP)
                - module.scale_vector(challenge_polynomial, public_vector, QP)
            )
            low = decomposition.low_bits(rebuilt, context.rounding_step, QP)
            simulated += int(np.abs(low).max()) < gamma2 - beta
        real_reached, real_passed = 0, 0
        while real_reached < trials:
            challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
            attempt = self._attempt(challenge)
            if attempt.response_ok:
                real_reached += 1
                real_passed += attempt.low_ok
        expected = ((2 * (gamma2 - beta) - 1) / (2 * gamma2)) ** (self.rank * D)
        self.assertAlmostEqual(simulated / trials, expected, delta=0.12)
        self.assertAlmostEqual(real_passed / trials, expected, delta=0.12)

    def test_released_responses_are_uniform_on_their_box(self) -> None:
        # The simulator's distribution for z. Marginal statistics only: support, first
        # two moments and a chi-square over 32 bins of about 115000 coefficients.
        bound = self.parameters["gamma1"] - self.parameters["beta"]
        responses = []
        for _ in range(150):
            challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
            responses.append(self._proof(challenge)[0].reshape(-1))
        values = np.concatenate(responses)
        self.assertLess(int(np.abs(values).max()), bound)
        self.assertGreater(int(np.abs(values).max()), bound - 100)
        self.assertLess(abs(float(values.mean())) / bound, 0.01)
        self.assertAlmostEqual(float(values.std()) / bound, 1 / np.sqrt(3), delta=0.005)

        support = 2 * bound - 1
        bins = 32
        observed = np.bincount((values + bound - 1) * bins // support, minlength=bins)
        bin_sizes = np.bincount(np.arange(support) * bins // support, minlength=bins)
        expected = values.size * bin_sizes / support
        chi_square = float(((observed - expected) ** 2 / expected).sum())
        # 31 degrees of freedom: mean 31, standard deviation 7.9.
        self.assertLess(chi_square, 90)

    def test_estimator_that_broke_the_previous_construction_learns_nothing(self) -> None:
        # Least squares on (c, z) recovered the whole key from four tokens when the mask
        # was CBD(eta) (see ManuscriptDeviationTests). With the uniform mask and the
        # rejection, sixty tokens give an estimate unrelated to the secret.
        _, _, _, secret, _, _ = self._internals()
        pairs = []
        for _ in range(60):
            challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
            response, _, challenge_polynomial = self._proof(challenge)
            pairs.append((challenge_polynomial, response))
        estimate = _least_squares_estimate(pairs)
        correlation = float(np.corrcoef(estimate.reshape(-1), secret.reshape(-1))[0, 1])
        self.assertLess(abs(correlation), 0.2)
        guess = np.clip(np.rint(estimate), -ETA, ETA).astype(np.int64)
        # Guessing zero everywhere is right for 37.5 % of CBD(2) coefficients.
        self.assertLess(float((guess == secret).mean()), 0.25)
        self.assertGreater(float(np.abs(estimate).std()), 100)

    def test_value_the_verifier_rebuilds_is_not_the_error_term(self) -> None:
        # In the manuscript's check the verifier computed -c e, bounded by beta. Now it
        # computes w - c e, whose low part is spread over the whole rounding interval.
        gamma2, beta = self.parameters["gamma2"], self.parameters["beta"]
        challenge = self.protocol.generate_challenge(self.system_parameters, self.public_key)
        response, _, challenge_polynomial = self._proof(challenge)
        low = decomposition.low_bits(self._rebuilt(response, challenge_polynomial), 2 * gamma2, QP)
        self.assertGreater(int(np.abs(low).max()), 100 * beta)
        self.assertLess(int(np.abs(low).max()), gamma2 - beta)
        self.assertGreater(float(low.std()), gamma2 / 4)


if __name__ == "__main__":
    unittest.main()
