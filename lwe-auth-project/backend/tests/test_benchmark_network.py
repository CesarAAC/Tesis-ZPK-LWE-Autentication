import unittest

from benchmarking.config import NetworkScenario
from benchmarking.network import projected_transport_time_ms


class BenchmarkNetworkTests(unittest.TestCase):
    def test_projection_combines_rtt_and_serialization_delay(self) -> None:
        scenario = NetworkScenario(name="test", rtt_ms=50.0, bandwidth_mbps=1.0)
        # 125,000 bytes = 1,000,000 bits = one second at 1 Mbps.
        self.assertAlmostEqual(
            projected_transport_time_ms(125_000, scenario),
            1050.0,
        )


if __name__ == "__main__":
    unittest.main()
