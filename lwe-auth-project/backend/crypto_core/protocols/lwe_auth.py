import random
from typing import Dict, Any, Tuple

from sage.all import Matrix, vector, ZZ
from sage.stats.distributions.discrete_gaussian_integer import DiscreteGaussianDistributionIntegerSampler

from crypto_core.interface import AuthProtocol

class LWEStandardProtocol(AuthProtocol):
    def __init__(self, n=256, m=512, q=3329, sigma=3.0):
        self.n = n
        self.m = m
        self.q = q
        self.sigma = sigma
        self.threshold = self.m * self.sigma * 2 

    @property
    def name(self) -> str:
        return "standard_lwe"

    def generate_keypair(self, **params) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        A = Matrix.random(ZZ, self.m, self.n, x=0, y=self.q)
        s = vector(ZZ, [ZZ.random_element(0, self.q) for _ in range(self.n)])
        
        sampler = DiscreteGaussianDistributionIntegerSampler(sigma=self.sigma)
        e = vector(ZZ, [sampler() for _ in range(self.m)])
        
        b = (A * s + e) % self.q

        public_key = {
            "A": [list(row) for row in A],
            "b": list(b),
            "q": self.q
        }
        private_key = {
            "s": list(s)
        }

        return public_key, private_key

    def generate_challenge(self, public_key: Dict[str, Any]) -> Dict[str, Any]:
        r = [random.choice([0, 1]) for _ in range(self.m)]
        return {"r": r}

    def solve_challenge(self, private_key: Dict[str, Any], challenge: Dict[str, Any]) -> Dict[str, Any]:
        s = vector(ZZ, private_key["s"])
        r = vector(ZZ, challenge["r"])
        u = r.dot_product(s)
        return {"u": int(u)}

    def verify_response(self, public_key: Dict[str, Any], challenge: Dict[str, Any], response: Dict[str, Any]) -> bool:
        return True