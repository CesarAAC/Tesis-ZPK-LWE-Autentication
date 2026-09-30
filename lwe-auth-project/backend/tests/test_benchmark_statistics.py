import unittest

from benchmarking.statistics import summarize_measurements
from benchmarking.types import Measurement


class BenchmarkStatisticsTests(unittest.TestCase):
    def test_summary_contains_required_descriptive_statistics(self) -> None:
        measurements = [
            Measurement("timing", "verify", "wall_time", value, "ms", index)
            for index, value in enumerate([1.0, 2.0, 3.0, 4.0, 5.0])
        ]
        [summary] = summarize_measurements(measurements)
        self.assertEqual(summary.sample_count, 5)
        self.assertEqual(summary.mean, 3.0)
        self.assertEqual(summary.median, 3.0)
        self.assertEqual(summary.minimum, 1.0)
        self.assertEqual(summary.maximum, 5.0)
        self.assertGreater(summary.p95, 4.0)
        self.assertGreater(summary.p99, summary.p95)

    def test_derived_measurements_without_iteration_are_not_summarized(self) -> None:
        measurements = [
            Measurement(
                "network_projection",
                "authentication",
                "transport_time",
                10.0,
                "ms",
                None,
                {"scenario": "x"},
            )
        ]
        self.assertEqual(summarize_measurements(measurements), [])


if __name__ == "__main__":
    unittest.main()
