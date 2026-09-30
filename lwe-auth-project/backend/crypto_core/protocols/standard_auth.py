import os
import base64
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from crypto_core.interface import AuthProtocol

class StandardECDSAProtocol(AuthProtocol):
    @property
    def name(self) -> str:
        return "standard_ecdsa"

    def generate_keypair(self, **params) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        # Generar clave privada usando la curva elíptica P-256
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        # Serializar clave privada a PEM
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Serializar clave pública a PEM
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Devolvemos diccionarios con las claves en Base64 para guardarlas en JSONB
        private_data = {"key_pem": base64.b64encode(priv_bytes).decode('utf-8')}
        public_data = {"key_pem": base64.b64encode(pub_bytes).decode('utf-8')}

        return public_data, private_data

    def generate_challenge(self, public_key: Dict[str, Any]) -> Dict[str, Any]:
        # Generar un desafío aleatorio de 32 bytes (nonce)
        nonce = os.urandom(32)
        return {"nonce": base64.b64encode(nonce).decode('utf-8')}

    def solve_challenge(self, private_key: Dict[str, Any], challenge: Dict[str, Any]) -> Dict[str, Any]:
        # Decodificar la clave privada PEM
        priv_bytes = base64.b64decode(private_key["key_pem"])
        priv_key_obj = serialization.load_pem_private_key(
            priv_bytes,
            password=None
        )

        # Decodificar el desafío
        nonce = base64.b64decode(challenge["nonce"])

        # Firmar el desafío (el cliente demuestra que posee la clave privada)
        signature = priv_key_obj.sign(
            nonce,
            ec.ECDSA(hashes.SHA256())
        )

        return {"signature": base64.b64encode(signature).decode('utf-8')}

    def verify_response(
        self, public_key: Dict[str, Any], challenge: Dict[str, Any], response: Dict[str, Any]
    ) -> bool:
        try:
            # Decodificar la clave pública PEM
            pub_bytes = base64.b64decode(public_key["key_pem"])
            pub_key_obj = serialization.load_pem_public_key(pub_bytes)

            # Decodificar desafío y respuesta (firma)
            nonce = base64.b64decode(challenge["nonce"])
            signature = base64.b64decode(response["signature"])

            # Verificar la firma
            pub_key_obj.verify(
                signature,
                nonce,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            print(f"Error en verificación: {e}")
            return False