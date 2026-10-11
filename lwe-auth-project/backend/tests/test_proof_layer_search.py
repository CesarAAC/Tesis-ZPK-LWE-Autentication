import json
import os
import tempfile
import unittest
from pathlib import Path

from benchmarking import hardness, proof_layer_search
from crypto_core.protocols.proposed_lwe import ProposedLWEAuthProtocol

ESTIMATOR = os.environ.get("LATTICE_ESTIMATOR_PATH", "/estimator")

# Table "Búsqueda de (k', eta')" of chapter 4: (k', eta') -> (key bits, acceptance, mean attempts).
THESIS_TABLE = {
    (3, 2): (78.8, 0.525, 1.9),
    (4, 2): (114.9, 0.423, 2.4),
    (4, 4): (122.6, 0.180, 5.6),
    (4, 5): (126.1, 0.117, 8.5),
    (4, 6): (128.2, 0.077, 13.1),
    (4, 7): (129.9, 0.050, 20.0),
    (4, 8): (131.4, 0.033, 30.7),
    (5, 2): (152.4, 0.341, 2.9),
}


class AcceptanceColumnTests(unittest.TestCase):
    def test_default_grid_is_the_thesis_table(self) -> None:
        self.assertEqual(set(proof_layer_search.DEFAULT_GRID), set(THESIS_TABLE))

    def test_acceptance_and_attempts_match_the_thesis_table(self) -> None:
        for (rank, eta), (_, acceptance, attempts) in THESIS_TABLE.items():
            with self.subTest(k_proof=rank, eta_proof=eta):
                row = proof_layer_search.evaluate(rank, eta)
                self.assertEqual(round(row["acceptance_probability"], 3), acceptance)
                self.assertEqual(round(row["mean_attempts"], 1), attempts)
                self.assertIsNone(row["key_classical_bits"])

    def test_chosen_row_uses_the_protocol_defaults(self) -> None:
        defaults = ProposedLWEAuthProtocol().resolve_parameters({})
        parameters = proof_layer_search.search_parameters(defaults["k_proof"], defaults["eta_proof"])
        self.assertEqual(parameters, dict(defaults))
        self.assertEqual(parameters["beta"], 138)

    def test_cli_without_estimator_writes_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "search.json"
            proof_layer_search.main(["--without-hardness", "--grid", "4:6,5:2", "--output", str(output)])
            rows = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual([(row["k_proof"], row["eta_proof"]) for row in rows], [(4, 6), (5, 2)])


@unittest.skipUnless(Path(ESTIMATOR, "estimator").is_dir(), "lattice-estimator is not mounted")
class HardnessColumnTests(unittest.TestCase):
    def test_key_hardness_matches_the_thesis_table(self) -> None:
        estimator = hardness.load_estimator(ESTIMATOR)
        for (rank, eta), (bits, _, _) in THESIS_TABLE.items():
            with self.subTest(k_proof=rank, eta_proof=eta):
                row = proof_layer_search.evaluate(rank, eta, estimator)
                self.assertEqual(round(row["key_classical_bits"], 1), bits)


if __name__ == "__main__":
    unittest.main()
