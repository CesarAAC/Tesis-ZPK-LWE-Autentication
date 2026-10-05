import json
import os
import tempfile
import unittest
from pathlib import Path

from benchmarking import hardness, hardness_cli
from benchmarking.config import BenchmarkConfig
from benchmarking.security import SecurityAssessment
from crypto_core.exceptions import CryptoCoreError
from crypto_core.registry import available_protocol_names, get_protocol

CONFIG = Path(__file__).resolve().parents[1] / "benchmarking" / "configs" / "default.json"
ESTIMATOR = os.environ.get("LATTICE_ESTIMATOR_PATH", "/estimator")


def _parameters(protocol_id: str) -> dict:
    config = BenchmarkConfig.from_json_file(CONFIG)
    return get_protocol(protocol_id).resolve_parameters(config.protocol_parameters.get(protocol_id, {}))


def _by_role(protocol_id: str) -> dict:
    return {instance.role: instance for instance in hardness.instances(protocol_id, _parameters(protocol_id))}


class InstanceMappingTests(unittest.TestCase):
    def test_every_lattice_candidate_has_a_key_and_a_soundness_instance(self) -> None:
        for protocol_id in available_protocol_names():
            if protocol_id in hardness.LITERATURE:
                continue
            with self.subTest(protocol=protocol_id):
                roles = _by_role(protocol_id)
                self.assertIsInstance(roles["clave"], hardness.LWEInstance)
                self.assertIsInstance(roles["solidez"], hardness.SISInstance)

    def test_proposed_lwe_uses_the_proof_layer_at_rank_four(self) -> None:
        roles = _by_role("proposed_lwe")
        key, soundness, transport = roles["clave"], roles["solidez"], roles["transporte"]
        self.assertEqual((key.n, key.m, key.q), (1024, 1024, 8380417))
        self.assertEqual((soundness.rows, soundness.columns, soundness.bound), (1024, 2304, 131026))
        self.assertEqual((transport.n, transport.q), (768, 3329))

    def test_matched_parameter_sets_of_the_baselines(self) -> None:
        standard, binary, lwr, ring = (_by_role(name) for name in ("standard_lwe", "binary_lwe", "lwr", "ring_lwe"))
        self.assertEqual((standard["clave"].n, standard["clave"].secret), (1024, ("centered_binomial", 2)))
        self.assertEqual((binary["clave"].n, binary["clave"].secret), (1096, ("uniform", 0, 1)))
        self.assertEqual((lwr["clave"].n, lwr["clave"].error), (1016, ("uniform", -1, 2)))
        self.assertEqual((ring["clave"].n, ring["solidez"].columns), (1024, 3072))
        # SIS bound = norm of an accepted response: gamma - kappa * (largest witness coefficient).
        self.assertEqual(standard["solidez"].bound, (1 << 17) - 31 * 2)
        self.assertEqual(binary["solidez"].bound, (1 << 17) - 31)
        self.assertEqual(standard["solidez"].columns, 1024 + 1024 + 128)

    def test_lwr_error_interval_matches_the_rounding_of_the_implementation(self) -> None:
        import numpy as np

        from crypto_core.lwe import lwr

        q, p = 1 << 23, 1 << 21
        values = np.arange(0, 4 * (q // p) * 64)
        errors = (q // p) * lwr.round_q_to_p(values, q, p) - values
        _, low, high = _by_role("lwr")["clave"].error
        self.assertEqual((int(errors.min()), int(errors.max())), (low, high))

    def test_ecdsa_is_cited_not_estimated(self) -> None:
        with self.assertRaises(CryptoCoreError):
            hardness.instances("ecdsa", {})
        self.assertEqual(hardness.LITERATURE["ecdsa"]["quantum_security_bits"], 0.0)

    def test_missing_estimator_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(CryptoCoreError):
                hardness.load_estimator(Path(directory) / "missing")


class CliTests(unittest.TestCase):
    def test_literature_assessment_is_ready_for_security_cli(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            hardness_cli.main(["--config", str(CONFIG), "--protocol", "ecdsa", "--output-dir", directory])
            assessment = SecurityAssessment.from_json_file(Path(directory) / "ecdsa.security.json")
        assessment.assert_ready_for_persistence()
        self.assertEqual(assessment.classical_security_bits, 128.0)

    def test_checkout_commit_is_read_from_git_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".git" / "refs" / "heads").mkdir(parents=True)
            (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
            (root / ".git" / "refs" / "heads" / "main").write_text("abc123\n", encoding="utf-8")
            self.assertEqual(hardness_cli._checkout_commit(root), "abc123")
            self.assertIsNone(hardness_cli._checkout_commit(root / "nothing"))


@unittest.skipUnless(Path(ESTIMATOR, "estimator").is_dir(), "lattice-estimator is not mounted")
class EstimatorValidationTests(unittest.TestCase):
    """Published Core-SVP block sizes the pipeline must reproduce (Kyber and Dilithium round 3)."""

    def setUp(self) -> None:
        self.estimator = hardness.load_estimator(ESTIMATOR)

    def test_reproduces_kyber512_and_dilithium2(self) -> None:
        kyber = hardness.LWEInstance("clave", "Kyber512", 512, 512, 3329, ("centered_binomial", 3), ("centered_binomial", 3))
        self.assertEqual(hardness.estimate(self.estimator, kyber)["attacks"]["usvp"]["beta"], 406)
        dilithium = hardness.SISInstance("solidez", "Dilithium2", 1024, 9 * 256, 8380417, 350209)
        self.assertEqual(hardness.estimate(self.estimator, dilithium)["beta"], 423)

    def test_matched_candidates_are_within_one_bit_of_proposed_lwe(self) -> None:
        reference = None
        for protocol_id in ("proposed_lwe", "standard_lwe", "binary_lwe", "lwr", "ring_lwe"):
            key = hardness.estimate(self.estimator, _by_role(protocol_id)["clave"])
            reference = reference or key["classical_bits"]
            with self.subTest(protocol=protocol_id):
                self.assertAlmostEqual(key["classical_bits"], reference, delta=1.0)


if __name__ == "__main__":
    unittest.main()
