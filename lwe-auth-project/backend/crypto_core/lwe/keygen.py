from dataclasses import dataclass
from typing import Callable

from sage.all import Matrix, ZZ, vector
from sage.stats.distributions.discrete_gaussian_integer import (
    DiscreteGaussianDistributionIntegerSampler,
)

from crypto_core.interface import KeyPair, SerializedData


@dataclass(frozen=True, slots=True)
class LWEParameters:
    """Parameters shared by the current Standard-LWE key generators."""

    n: int = 256
    m: int = 512
    q: int = 3329
    sigma: float = 3.0

    def __post_init__(self) -> None:
        if self.n <= 0 or self.m <= 0:
            raise ValueError("n y m deben ser enteros positivos.")
        if self.q < 2:
            raise ValueError("q debe ser al menos 2.")
        if self.sigma <= 0:
            raise ValueError("sigma debe ser positivo.")


def _generate_keypair(
    params: LWEParameters,
    sample_secret_coefficient: Callable[[], object],
) -> KeyPair:
    matrix_a = Matrix.random(ZZ, params.m, params.n, x=0, y=params.q)
    secret = vector(
        ZZ,
        [sample_secret_coefficient() for _ in range(params.n)],
    )

    sampler = DiscreteGaussianDistributionIntegerSampler(sigma=params.sigma)
    error = vector(ZZ, [sampler() for _ in range(params.m)])
    vector_b = (matrix_a * secret + error) % params.q

    public_key: SerializedData = {
        "A": [[int(value) for value in row] for row in matrix_a],
        "b": [int(value) for value in vector_b],
        "q": params.q,
    }
    private_key: SerializedData = {
        "s": [int(value) for value in secret],
    }
    return public_key, private_key


def generate_standard_lwe_keypair(params: LWEParameters | None = None) -> KeyPair:
    """Generate A, b = A*s + e (mod q) with s sampled uniformly in Z_q^n."""
    resolved = params or LWEParameters()
    return _generate_keypair(
        resolved,
        lambda: ZZ.random_element(0, resolved.q),
    )


def generate_binary_lwe_keypair(params: LWEParameters | None = None) -> KeyPair:
    """Generate LWE key material with a binary secret s in {0, 1}^n."""
    resolved = params or LWEParameters()
    return _generate_keypair(
        resolved,
        lambda: ZZ.random_element(0, 2),
    )
