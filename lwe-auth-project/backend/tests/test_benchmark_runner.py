import unittest

from benchmarking.config import BenchmarkConfig, NetworkScenario
from benchmarking.runner import BenchmarkRunner
from crypto_core.registry import get_protocol_spec


class BenchmarkRunnerTests(unittest.TestCase):
    def test_small_ecdsa_run_produces_required_metric_families(self) -> None:
        config = BenchmarkConfig(
            warmup_iterations=1,
            timing_iterations=3,
            authentication_key_sets=2,
            memory_iterations=0,
            cooldown_seconds_between_protocols=0,
            randomize_protocol_order=False,
            network_scenarios=[
                NetworkScenario(name="test", rtt_ms=10, bandwidth_mbps=10)
            ],
            protocol_parameters={"ecdsa": {}},
        )
        result = BenchmarkRunner(config).run_protocol(get_protocol_spec("ecdsa"))
        categories = {item.category for item in result.measurements}
        self.assertTrue(
            {
                "implementation",
                "timing",
                "artifact_size",
                "storage",
                "communication",
                "serialization",
                "throughput",
                "network_projection",
            }.issubset(categories)
        )
        operations = {(item.category, item.operation) for item in result.measurements}
        self.assertIn(("timing", "setup"), operations)
        self.assertIn(("timing", "keygen"), operations)
        self.assertIn(("timing", "authentication"), operations)
        self.assertIn(("storage", "shared_deployment"), operations)
        self.assertTrue(result.summaries)
        self.assertTrue(all(result.conformance_checks.values()))

        throughput = [
            item
            for item in result.measurements
            if item.category == "throughput"
            and item.operation == "authentication"
            and item.metric_name == "sequential_rate"
        ]
        self.assertEqual(len(throughput), 1)
        self.assertIsNone(throughput[0].iteration)
        self.assertEqual(throughput[0].metadata["sample_count"], 3)

        setup_sizes = [
            item.value
            for item in result.measurements
            if item.category == "artifact_size"
            and item.operation == "setup"
            and item.metric_name == "system_parameters"
        ]
        self.assertEqual(setup_sizes, [0.0, 0.0, 0.0])

    def test_experiment_records_config_fingerprint_and_timestamps(self) -> None:
        config = BenchmarkConfig(
            warmup_iterations=0,
            timing_iterations=1,
            memory_iterations=0,
            cooldown_seconds_between_protocols=0,
            randomize_protocol_order=False,
            protocol_parameters={"ecdsa": {}},
        )
        result = BenchmarkRunner(config).run_experiment(["ecdsa"])
        self.assertEqual(len(result.config_sha256), 64)
        self.assertEqual(result.protocol_order, ["ecdsa"])
        self.assertTrue(result.started_at_utc.endswith("+00:00"))
        self.assertTrue(result.finished_at_utc.endswith("+00:00"))


if __name__ == "__main__":
    unittest.main()
