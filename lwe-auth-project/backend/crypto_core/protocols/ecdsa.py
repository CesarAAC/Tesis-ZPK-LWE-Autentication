import base64
import binascii
import secrets
from typing import Any

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from crypto_core.exceptions import InvalidProtocolDataError
from crypto_core.interface import AuthProtocol, KeyPair, SerializedData

_NONCE_SIZE_BYTES = 32
_CURVE = ec.SECP256R1()


def _decode_base64(value: Any, field_name: str) -> bytes:
    if not isinstance(value, str):
        raise InvalidProtocolDataError(f"'{field_name}' debe ser un string Base64.")

    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidProtocolDataError(
            f"'{field_name}' no contiene Base64 válido."
        ) from exc


def _load_private_key(private_key: SerializedData) -> ec.EllipticCurvePrivateKey:
    try:
        encoded_key = private_key["key_pem"]
    except KeyError as exc:
        raise InvalidProtocolDataError("Falta 'key_pem' en la clave privada.") from exc

    try:
        key = serialization.load_pem_private_key(
            _decode_base64(encoded_key, "key_pem"),
            password=None,
        )
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise InvalidProtocolDataError("La clave privada PEM no es válida.") from exc

    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != _CURVE.name:
        raise InvalidProtocolDataError("Se esperaba una clave privada ECDSA P-256.")

    return key


def _load_public_key(public_key: SerializedData) -> ec.EllipticCurvePublicKey:
    try:
        encoded_key = public_key["key_pem"]
    except KeyError as exc:
        raise InvalidProtocolDataError("Falta 'key_pem' en la clave pública.") from exc

    try:
        key = serialization.load_pem_public_key(_decode_base64(encoded_key, "key_pem"))
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise InvalidProtocolDataError("La clave pública PEM no es válida.") from exc

    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != _CURVE.name:
        raise InvalidProtocolDataError("Se esperaba una clave pública ECDSA P-256.")

    return key


class StandardECDSAProtocol(AuthProtocol):
    """Baseline challenge/response authentication using ECDSA over P-256."""

    @property
    def name(self) -> str:
        return "standard_ecdsa"

    def default_parameters(self) -> SerializedData:
        return {
            "curve": "secp256r1",
            "hash": "sha256",
            "challenge_bytes": _NONCE_SIZE_BYTES,
        }

    def resolve_parameters(
        self, overrides: SerializedData | None = None
    ) -> SerializedData:
        resolved = self.default_parameters()
        overrides = overrides or {}
        unknown = set(overrides) - set(resolved)
        if unknown:
            raise InvalidProtocolDataError(
                f"Parámetros ECDSA desconocidos: {sorted(unknown)}."
            )
        resolved.update(overrides)
        expected = self.default_parameters()
        if resolved != expected:
            raise InvalidProtocolDataError(
                "La implementación baseline fija ECDSA a P-256, SHA-256 y nonce de 32 bytes."
            )
        return resolved

    def generate_system_parameters(self, **params: Any) -> SerializedData:
        self.resolve_parameters(params)
        return {}

    def generate_keypair(
        self,
        system_parameters: SerializedData,
        **params: Any,
    ) -> KeyPair:
        if system_parameters != {}:
            raise InvalidProtocolDataError(
                "ECDSA no utiliza parámetros públicos generados durante setup."
            )
        self.resolve_parameters(params)
        private_key = ec.generate_private_key(_CURVE)
        public_key = private_key.public_key()

        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return (
            {"key_pem": base64.b64encode(public_bytes).decode("ascii")},
            {"key_pem": base64.b64encode(private_bytes).decode("ascii")},
        )

    def generate_challenge(
        self,
        system_parameters: SerializedData,
        public_key: SerializedData,
    ) -> SerializedData:
        if system_parameters != {}:
            raise InvalidProtocolDataError(
                "ECDSA no utiliza parámetros públicos generados durante setup."
            )
        # ECDSA does not need the public key to create a nonce, but the common
        # interface keeps the argument for protocols that do need it.
        del public_key
        nonce = secrets.token_bytes(_NONCE_SIZE_BYTES)
        return {"nonce": base64.b64encode(nonce).decode("ascii")}

    def solve_challenge(
        self,
        system_parameters: SerializedData,
        private_key: SerializedData,
        challenge: SerializedData,
    ) -> SerializedData:
        if system_parameters != {}:
            raise InvalidProtocolDataError(
                "ECDSA no utiliza parámetros públicos generados durante setup."
            )
        key = _load_private_key(private_key)

        try:
            encoded_nonce = challenge["nonce"]
        except KeyError as exc:
            raise InvalidProtocolDataError("Falta 'nonce' en el desafío.") from exc

        nonce = _decode_base64(encoded_nonce, "nonce")
        if len(nonce) != _NONCE_SIZE_BYTES:
            raise InvalidProtocolDataError("El nonce debe tener exactamente 32 bytes.")

        signature = key.sign(nonce, ec.ECDSA(hashes.SHA256()))
        return {"signature": base64.b64encode(signature).decode("ascii")}

    def verify_response(
        self,
        system_parameters: SerializedData,
        public_key: SerializedData,
        challenge: SerializedData,
        response: SerializedData,
    ) -> bool:
        if system_parameters != {}:
            raise InvalidProtocolDataError(
                "ECDSA no utiliza parámetros públicos generados durante setup."
            )
        key = _load_public_key(public_key)

        try:
            encoded_nonce = challenge["nonce"]
            encoded_signature = response["signature"]
        except KeyError as exc:
            raise InvalidProtocolDataError(
                "El desafío o la respuesta no contienen los campos requeridos."
            ) from exc

        nonce = _decode_base64(encoded_nonce, "nonce")
        if len(nonce) != _NONCE_SIZE_BYTES:
            raise InvalidProtocolDataError("El nonce debe tener exactamente 32 bytes.")

        signature = _decode_base64(encoded_signature, "signature")

        try:
            key.verify(signature, nonce, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return False

        return True
