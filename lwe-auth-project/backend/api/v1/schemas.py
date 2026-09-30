from typing import Any, Dict

from pydantic import BaseModel, ConfigDict, Field

SerializedPayload = Dict[str, Any]


class StrictRequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProtocolRequest(StrictRequestModel):
    protocol_name: str = Field(min_length=1)


class ChallengeRequest(ProtocolRequest):
    public_key: SerializedPayload


class SolveRequest(ProtocolRequest):
    private_key: SerializedPayload
    challenge: SerializedPayload


class VerifyRequest(ProtocolRequest):
    public_key: SerializedPayload
    challenge: SerializedPayload
    response: SerializedPayload


class MethodsResponse(BaseModel):
    available_methods: list[str]


class KeyPairResponse(BaseModel):
    public_key: SerializedPayload
    private_key: SerializedPayload


class ChallengeResponse(BaseModel):
    challenge: SerializedPayload


class SolveResponse(BaseModel):
    response: SerializedPayload


class VerifyResponse(BaseModel):
    is_valid: bool
