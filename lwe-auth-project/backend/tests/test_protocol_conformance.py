import unittest

from benchmarking.conformance import run_conformance_checks
from crypto_core.protocols.ecdsa import StandardECDSAProtocol


class ProtocolConformanceTests(unittest.TestCase):
    def test_ecdsa_satisfies_common_benchmark_contract(self) -> None:
        protocol = StandardECDSAProtocol()
        checks = run_conformance_checks(protocol, protocol.resolve_parameters())
        self.assertTrue(all(checks.values()))


if __name__ == "__main__":
    unittest.main()
