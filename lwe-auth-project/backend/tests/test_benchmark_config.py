import unittest
from pathlib import Path

from pydantic import ValidationError

from benchmarking.config import BenchmarkConfig, NetworkScenario


class BenchmarkConfigTests(unittest.TestCase):
    def test_network_scenario_names_must_be_unique(self) -> None:
        with self.assertRaises(ValidationError):
            BenchmarkConfig(
                timing_iterations=1,
                network_scenarios=[
                    NetworkScenario(name="same", rtt_ms=1, bandwidth_mbps=10),
                    NetworkScenario(name="same", rtt_ms=2, bandwidth_mbps=20),
                ],
            )

    def test_memory_measurements_can_be_disabled_for_fast_smoke_tests(self) -> None:
        config = BenchmarkConfig(timing_iterations=1, memory_iterations=0)
        self.assertEqual(config.memory_iterations, 0)

    def test_unknown_configuration_keys_are_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            BenchmarkConfig.model_validate(
                {
                    "timing_iterations": 1,
                    "shuffle_protocol_order": True,
                }
            )

    def test_default_configuration_file_matches_schema(self) -> None:
        config_path = Path(__file__).parents[1] / "benchmarking" / "configs" / "default.json"
        config = BenchmarkConfig.from_json_file(config_path)
        self.assertEqual(config.authentication_key_sets, 5)
        self.assertTrue(config.randomize_protocol_order)
        self.assertGreaterEqual(len(config.network_scenarios), 1)


if __name__ == "__main__":
    unittest.main()
