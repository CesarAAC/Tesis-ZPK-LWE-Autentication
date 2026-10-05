import unittest

from benchmarking.conformance import run_conformance_checks
from crypto_core.protocols.ecdsa import StandardECDSAProtocol
from crypto_core.protocols.lwe_zk import BinaryLWEProtocol, StandardLWEProtocol
from crypto_core.protocols.lwr_auth import LWRProtocol
from crypto_core.protocols.proposed_lwe import ProposedLWEAuthProtocol
from crypto_core.protocols.ring_lwe import RingLWEProtocol


class ProtocolConformanceTests(unittest.TestCase):
    def test_ecdsa_satisfies_common_benchmark_contract(self) -> None:
        protocol = StandardECDSAProtocol()
        checks = run_conformance_checks(protocol, protocol.resolve_parameters())
        self.assertTrue(all(checks.values()))

    def test_lattice_candidates_satisfy_common_benchmark_contract_with_defaults(self) -> None:
        for protocol in (
            StandardLWEProtocol(),
            BinaryLWEProtocol(),
            RingLWEProtocol(),
            LWRProtocol(),
            ProposedLWEAuthProtocol(),
        ):
            with self.subTest(protocol=protocol.name):
                checks = run_conformance_checks(protocol, protocol.resolve_parameters())
                self.assertTrue(all(checks.values()))


if __name__ == "__main__":
    unittest.main()
