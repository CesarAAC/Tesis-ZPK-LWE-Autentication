from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any

# Importar los protocolos (Ajusta las rutas si es necesario)
from crypto_core.protocols.standard_auth import StandardECDSAProtocol
from crypto_core.protocols.lwe_auth import LWEStandardProtocol
from crypto_core.protocols.binary_lwe import BinaryLWEProtocol

app = FastAPI(title="LWE Cripto Comparador API")

# Registro estático de protocolos disponibles
PROTOCOLS = {
    "standard": StandardECDSAProtocol(),
    "lwe": LWEStandardProtocol(),
    "binary_lwe": BinaryLWEProtocol()
}

# --- Modelos Pydantic para validar entradas ---
class ProtocolRequest(BaseModel):
    protocol_name: str  # "standard", "lwe", "binary_lwe"

class ChallengeRequest(BaseModel):
    protocol_name: str
    public_key: Dict[str, Any]

class SolveRequest(BaseModel):
    protocol_name: str
    private_key: Dict[str, Any]
    challenge: Dict[str, Any]

class VerifyRequest(BaseModel):
    protocol_name: str
    public_key: Dict[str, Any]
    challenge: Dict[str, Any]
    response: Dict[str, Any]

# --- Endpoints ---
@app.get("/api/v1/methods")
def get_methods():
    """Devuelve la lista de protocolos soportados."""
    return {"available_methods": list(PROTOCOLS.keys())}

@app.post("/api/v1/generate_keys")
def generate_keys(req: ProtocolRequest):
    """Genera par de claves pública y privada."""
    if req.protocol_name not in PROTOCOLS:
        raise HTTPException(status_code=404, detail="Protocolo no encontrado")
    
    protocol = PROTOCOLS[req.protocol_name]
    public_key, private_key = protocol.generate_keypair()
    return {"public_key": public_key, "private_key": private_key}

@app.post("/api/v1/challenge")
def generate_challenge(req: ChallengeRequest):
    """El servidor genera un desafío."""
    if req.protocol_name not in PROTOCOLS:
        raise HTTPException(status_code=404, detail="Protocolo no encontrado")
    
    protocol = PROTOCOLS[req.protocol_name]
    challenge = protocol.generate_challenge(req.public_key)
    return {"challenge": challenge}

@app.post("/api/v1/solve")
def solve_challenge(req: SolveRequest):
    """Simula al cliente resolviendo el desafío."""
    if req.protocol_name not in PROTOCOLS:
        raise HTTPException(status_code=404, detail="Protocolo no encontrado")
    
    protocol = PROTOCOLS[req.protocol_name]
    response = protocol.solve_challenge(req.private_key, req.challenge)
    return {"response": response}

@app.post("/api/v1/verify")
def verify_response(req: VerifyRequest):
    """El servidor verifica la respuesta matemática."""
    if req.protocol_name not in PROTOCOLS:
        raise HTTPException(status_code=404, detail="Protocolo no encontrado")
    
    protocol = PROTOCOLS[req.protocol_name]
    is_valid = protocol.verify_response(req.public_key, req.challenge, req.response)
    return {"is_valid": is_valid}