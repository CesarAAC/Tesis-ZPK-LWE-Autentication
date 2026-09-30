from typing import Any, Dict

from pydantic import BaseModel, ConfigDict, Field

SerializedPayload = Dict[str, Any]


class StrictRequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProtocolRequest(StrictRequestModel):
    protocol_name: str = Field(min_length=1)
    parameters: SerializedPayload = Field(default_factory=dict)


class ChallengeRequest(StrictRequestModel):
    protocol_name: str = Field(min_length=1)
    system_parameters: SerializedPayload = Field(default_factory=dict)
    public_key: SerializedPayload


class SolveRequest(StrictRequestModel):
    protocol_name: str = Field(min_length=1)
    system_parameters: SerializedPayload = Field(default_factory=dict)
    private_key: SerializedPayload
    challenge: SerializedPayload


class VerifyRequest(StrictRequestModel):
    protocol_name: str = Field(min_length=1)
    system_parameters: SerializedPayload = Field(default_factory=dict)
    public_key: SerializedPayload
    challenge: SerializedPayload
    response: SerializedPayload


class MethodsResponse(BaseModel):
    available_methods: list[str]


class ProtocolCatalogEntry(BaseModel):
    protocol_id: str
    display_name: str
    family: str
    available: bool
    aliases: list[str]
    declared_dependencies: list[str]
    development_note: str


class ProtocolCatalogResponse(BaseModel):
    protocols: list[ProtocolCatalogEntry]


class KeyPairResponse(BaseModel):
    system_parameters: SerializedPayload
    public_key: SerializedPayload
    private_key: SerializedPayload
    effective_parameters: SerializedPayload


class ChallengeResponse(BaseModel):
    challenge: SerializedPayload


class SolveResponse(BaseModel):
    response: SerializedPayload


class VerifyResponse(BaseModel):
    is_valid: bool
