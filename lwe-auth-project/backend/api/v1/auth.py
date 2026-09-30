from fastapi import APIRouter, HTTPException, status

from api.v1.schemas import (
    ChallengeRequest,
    ChallengeResponse,
    KeyPairResponse,
    MethodsResponse,
    ProtocolCatalogEntry,
    ProtocolCatalogResponse,
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
from crypto_core.registry import (
    available_protocol_names,
    get_protocol,
    protocol_catalog,
)

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
    """List canonical identifiers for protocols ready for the complete flow."""
    return MethodsResponse(available_methods=list(available_protocol_names()))


@router.get("/protocols", response_model=ProtocolCatalogResponse)
def get_protocols() -> ProtocolCatalogResponse:
    """Expose all six thesis candidates and their implementation status."""
    return ProtocolCatalogResponse(
        protocols=[
            ProtocolCatalogEntry(
                protocol_id=spec.protocol_id,
                display_name=spec.display_name,
                family=spec.family,
                available=spec.available,
                aliases=list(spec.aliases),
                declared_dependencies=list(spec.declared_dependencies),
                development_note=spec.development_note,
            )
            for spec in protocol_catalog()
        ]
    )


@router.post("/generate_keys", response_model=KeyPairResponse)
def generate_keys(request: ProtocolRequest) -> KeyPairResponse:
    """Generate enrollment material and return the exact effective parameters."""
    protocol = _resolve_protocol(request.protocol_name)
    try:
        effective_parameters = protocol.resolve_parameters(request.parameters)
        system_parameters = protocol.generate_system_parameters(**effective_parameters)
        public_key, private_key = protocol.generate_keypair(
            system_parameters,
            **effective_parameters,
        )
    except InvalidProtocolDataError as exc:
        raise _invalid_payload(exc) from exc
    return KeyPairResponse(
        system_parameters=system_parameters,
        public_key=public_key,
        private_key=private_key,
        effective_parameters=effective_parameters,
    )


@router.post("/challenge", response_model=ChallengeResponse)
def generate_challenge(request: ChallengeRequest) -> ChallengeResponse:
    protocol = _resolve_protocol(request.protocol_name)
    try:
        challenge = protocol.generate_challenge(
            request.system_parameters,
            request.public_key,
        )
    except InvalidProtocolDataError as exc:
        raise _invalid_payload(exc) from exc
    return ChallengeResponse(challenge=challenge)


@router.post("/solve", response_model=SolveResponse)
def solve_challenge(request: SolveRequest) -> SolveResponse:
    """Development endpoint that simulates the prover/client side."""
    protocol = _resolve_protocol(request.protocol_name)
    try:
        response = protocol.solve_challenge(
            request.system_parameters,
            request.private_key,
            request.challenge,
        )
    except InvalidProtocolDataError as exc:
        raise _invalid_payload(exc) from exc
    return SolveResponse(response=response)


@router.post("/verify", response_model=VerifyResponse)
def verify_response(request: VerifyRequest) -> VerifyResponse:
    protocol = _resolve_protocol(request.protocol_name)
    try:
        is_valid = protocol.verify_response(
            request.system_parameters,
            request.public_key,
            request.challenge,
            request.response,
        )
    except InvalidProtocolDataError as exc:
        raise _invalid_payload(exc) from exc
    return VerifyResponse(is_valid=is_valid)
