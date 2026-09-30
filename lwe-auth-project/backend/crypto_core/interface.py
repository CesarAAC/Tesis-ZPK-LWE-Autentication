from abc import ABC, abstractmethod
from typing import Dict, Any, Tuple

class AuthProtocol(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Nombre identificador del protocolo."""
        pass

    @abstractmethod
    def generate_keypair(self, **params) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Devuelve (public_key, private_key) serializables para la DB.
        """
        pass

    @abstractmethod
    def generate_challenge(self, public_key: Dict[str, Any]) -> Dict[str, Any]:
        """
        Crea un desafío (challenge) que el cliente debe responder.
        """
        pass

    @abstractmethod
    def solve_challenge(self, private_key: Dict[str, Any], challenge: Dict[str, Any]) -> Dict[str, Any]:
        """
        Lógica del cliente para responder al desafío.
        """
        pass

    @abstractmethod
    def verify_response(
        self, public_key: Dict[str, Any], challenge: Dict[str, Any], response: Dict[str, Any]
    ) -> bool:
        """
        Valida matemáticamente la respuesta entregada por el cliente.
        """
        pass