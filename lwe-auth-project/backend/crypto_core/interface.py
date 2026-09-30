from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Tuple

SerializedData = Dict[str, Any]
KeyPair = Tuple[SerializedData, SerializedData]


class AuthProtocol(ABC):
    """Common contract used by the API and the benchmark harness.

    Every candidate exposes the same observable lifecycle:

    1. deployment/system setup (shared public material),
    2. per-user enrollment/key generation,
    3. fresh challenge generation,
    4. prover response,
    5. public verification.

    ``system_parameters`` are public, JSON-serializable material that may be shared
    by every user of one deployment (for example, a common matrix or ring
    description). If a protocol has no generated shared material, return ``{}``.
    Security-relevant configuration choices still belong in ``resolve_parameters``.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the implementation's canonical internal identifier."""
        raise NotImplementedError

    @abstractmethod
    def default_parameters(self) -> SerializedData:
        """Return every effective cryptographic parameter and its default value."""
        raise NotImplementedError

    @abstractmethod
    def resolve_parameters(self, overrides: SerializedData | None = None) -> SerializedData:
        """Validate overrides and return the complete effective parameter set."""
        raise NotImplementedError

    @abstractmethod
    def generate_system_parameters(self, **params: Any) -> SerializedData:
        """Generate public material shared by one deployment.

        Return an empty dictionary when no generated setup material is required.
        This operation is benchmarked separately from per-user enrollment.
        """
        raise NotImplementedError

    @abstractmethod
    def generate_keypair(
        self,
        system_parameters: SerializedData,
        **params: Any,
    ) -> KeyPair:
        """Return JSON-serializable public and private per-user enrollment material."""
        raise NotImplementedError

    @abstractmethod
    def generate_challenge(
        self,
        system_parameters: SerializedData,
        public_key: SerializedData,
    ) -> SerializedData:
        """Create a fresh challenge that the prover must answer."""
        raise NotImplementedError

    @abstractmethod
    def solve_challenge(
        self,
        system_parameters: SerializedData,
        private_key: SerializedData,
        challenge: SerializedData,
    ) -> SerializedData:
        """Produce the prover response for a challenge."""
        raise NotImplementedError

    @abstractmethod
    def verify_response(
        self,
        system_parameters: SerializedData,
        public_key: SerializedData,
        challenge: SerializedData,
        response: SerializedData,
    ) -> bool:
        """Validate a prover response without access to private key material."""
        raise NotImplementedError
