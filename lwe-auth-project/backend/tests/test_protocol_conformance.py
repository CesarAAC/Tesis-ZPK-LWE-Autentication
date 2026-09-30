import unittest

from benchmarking.conformance import run_conformance_checks
from crypto_core.protocols.ecdsa import StandardECDSAProtocol
from crypto_core.protocols.regev_lwe import BinaryLWEProtocol, StandardLWEProtocol
from crypto_core.protocols.ring_lwe import RingLWEProtocol
from crypto_core.protocols.lwr_auth import LWRProtocol


class ProtocolConformanceTests(unittest.TestCase):
    def test_ecdsa_satisfies_common_benchmark_contract(self) -> None:
        protocol = StandardECDSAProtocol()
        checks = run_conformance_checks(protocol, protocol.resolve_parameters())
        self.assertTrue(all(checks.values()))

    def test_lwe_candidates_satisfy_common_benchmark_contract(self) -> None:
        for protocol in (StandardLWEProtocol(), BinaryLWEProtocol()):
            with self.subTest(protocol=protocol.name):
                checks = run_conformance_checks(protocol, protocol.resolve_parameters())
                self.assertTrue(all(checks.values()))

    def test_ring_lwe_satisfies_common_benchmark_contract(self) -> None:
        protocol = RingLWEProtocol()
        parameters = protocol.resolve_parameters(
            {"n": 128, "q": 12289, "eta": 2, "message_bits": 128}
        )
        checks = run_conformance_checks(protocol, parameters)
        self.assertTrue(all(checks.values()))

    def test_lwr_satisfies_common_benchmark_contract(self) -> None:
        protocol = LWRProtocol()
        parameters = protocol.resolve_parameters(
            {"n": 64, "q": 4096, "p": 1024, "message_bits": 128}
        )
        checks = run_conformance_checks(protocol, parameters)
        self.assertTrue(all(checks.values()))


if __name__ == "__main__":
    unittest.main()
