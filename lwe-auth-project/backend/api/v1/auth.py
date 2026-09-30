from fastapi import APIRouter, HTTPException, status

from api.v1.schemas import (
    ChallengeRequest,
    ChallengeResponse,
    KeyPairResponse,
    MethodsResponse,
    ProtocolRequest,
    SolveRequest,
    SolveResponse,
    VerifyRequest,
    VerifyResponse,
)
from crypto_core.exceptions import (
    InvalidProtocolDataError,
    ProtocolUnavailableError,
    UnknownProtocolError,
)
from crypto_core.interface import AuthProtocol
from crypto_core.registry import available_protocol_names, get_protocol

router = APIRouter(tags=["authentication"])


def _resolve_protocol(protocol_name: str) -> AuthProtocol:
    try:
        return get_protocol(protocol_name)
    except ProtocolUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=str(exc),
        ) from exc
    except UnknownProtocolError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


def _invalid_payload(exc: InvalidProtocolDataError) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=str(exc),
    )


@router.get("/methods", response_model=MethodsResponse)
def get_methods() -> MethodsResponse:
    """List protocol identifiers that can complete the full authentication flow."""
    return MethodsResponse(available_methods=list(available_protocol_names()))


@router.post("/generate_keys", response_model=KeyPairResponse)
def generate_keys(request: ProtocolRequest) -> KeyPairResponse:
    """Generate public/private key material for an available protocol."""
    protocol = _resolve_protocol(request.protocol_name)
    public_key, private_key = protocol.generate_keypair()
    return KeyPairResponse(public_key=public_key, private_key=private_key)


@router.post("/challenge", response_model=ChallengeResponse)
def generate_challenge(request: ChallengeRequest) -> ChallengeResponse:
    """Generate a server-side challenge for a public key."""
    protocol = _resolve_protocol(request.protocol_name)
    try:
        challenge = protocol.generate_challenge(request.public_key)
    except InvalidProtocolDataError as exc:
        raise _invalid_payload(exc) from exc
    return ChallengeResponse(challenge=challenge)


@router.post("/solve", response_model=SolveResponse)
def solve_challenge(request: SolveRequest) -> SolveResponse:
    """Demo endpoint that simulates the prover/client side of the protocol."""
    protocol = _resolve_protocol(request.protocol_name)
    try:
        response = protocol.solve_challenge(request.private_key, request.challenge)
    except InvalidProtocolDataError as exc:
        raise _invalid_payload(exc) from exc
    return SolveResponse(response=response)


@router.post("/verify", response_model=VerifyResponse)
def verify_response(request: VerifyRequest) -> VerifyResponse:
    """Verify a prover response using only public material and the challenge."""
    protocol = _resolve_protocol(request.protocol_name)
    try:
        is_valid = protocol.verify_response(
            request.public_key,
            request.challenge,
            request.response,
        )
    except InvalidProtocolDataError as exc:
        raise _invalid_payload(exc) from exc
    return VerifyResponse(is_valid=is_valid)
