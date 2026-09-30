from abc import ABC, abstractmethod
from typing import Any, Dict, Tuple

SerializedData = Dict[str, Any]
KeyPair = Tuple[SerializedData, SerializedData]


class AuthProtocol(ABC):
    """Contract implemented by authentication mechanisms used by the prototype."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the canonical identifier of the protocol."""
        raise NotImplementedError

    @abstractmethod
    def generate_keypair(self, **params: Any) -> KeyPair:
        """Return JSON-serializable public and private key material."""
        raise NotImplementedError

    @abstractmethod
    def generate_challenge(self, public_key: SerializedData) -> SerializedData:
        """Create a challenge that the prover must answer."""
        raise NotImplementedError

    @abstractmethod
    def solve_challenge(
        self,
        private_key: SerializedData,
        challenge: SerializedData,
    ) -> SerializedData:
        """Produce the prover response for a challenge."""
        raise NotImplementedError

    @abstractmethod
    def verify_response(
        self,
        public_key: SerializedData,
        challenge: SerializedData,
        response: SerializedData,
    ) -> bool:
        """Validate a prover response without access to private key material."""
        raise NotImplementedError
