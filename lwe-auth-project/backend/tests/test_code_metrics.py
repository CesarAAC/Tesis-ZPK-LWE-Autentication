import unittest

from benchmarking.code_metrics import collect_implementation_metrics
from crypto_core.registry import get_protocol, get_protocol_spec


def _source_files(protocol_id: str) -> list[str]:
    protocol = get_protocol(protocol_id)
    measurements = collect_implementation_metrics(
        protocol,
        get_protocol_spec(protocol_id),
        protocol.resolve_parameters(),
    )
    measurement = next(
        measurement
        for measurement in measurements
        if measurement.metric_name == "source_lines_nonblank_noncomment"
    )
    return measurement.metadata["source_files"]


class CodeMetricsTests(unittest.TestCase):
    def test_standalone_protocol_counts_its_own_file_only(self) -> None:
        self.assertEqual(_source_files("ecdsa"), ["ecdsa.py"])
        self.assertEqual(_source_files("proposed_lwe"), ["proposed_lwe.py"])

    def test_shared_templates_are_included_for_every_lattice_candidate(self) -> None:
        expected = {
            "standard_lwe": ["lwe_zk.py", "matrix_lwe_zk.py", "lattice_zk.py"],
            "binary_lwe": ["lwe_zk.py", "matrix_lwe_zk.py", "lattice_zk.py"],
            "lwr": ["lwr_auth.py", "matrix_lwe_zk.py", "lattice_zk.py"],
            "ring_lwe": ["ring_lwe.py", "lattice_zk.py"],
        }
        for protocol_id, files in expected.items():
            with self.subTest(protocol_id=protocol_id):
                self.assertEqual(_source_files(protocol_id), files)


if __name__ == "__main__":
    unittest.main()
