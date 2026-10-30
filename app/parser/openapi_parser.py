"""OpenAPI parsing utilities for API Security Assistant.

This module provides functions to load an OpenAPI 3.x specification from a local JSON or YAML file
and extract a deterministic, JSON‑serialisable inventory of endpoints.

The implementation purposefully avoids any network calls, unsafe evaluation, or external $ref resolution.
Only local component references (e.g., ``#/components/parameters/...``) are resolved.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field, ValidationError, ConfigDict, model_validator

from ..config import MAX_SPEC_SIZE, SUPPORTED_METHODS


class SchemaModel(BaseModel):
    type: Optional[str] = None
    format: Optional[str] = None
    enum: Optional[List[Any]] = None
    default: Optional[Any] = None
    items: Optional[Dict[str, Any]] = None
    properties: Optional[Dict[str, Any]] = None
    description: Optional[str] = None


class ParameterModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    name: str
    location: str = Field(..., alias="in")
    required: bool = False
    schema: Optional[SchemaModel] = None
    description: Optional[str] = None


class MediaTypeModel(BaseModel):
    schema: Optional[SchemaModel] = None
    example: Optional[Any] = None
    examples: Optional[Dict[str, Any]] = None


class RequestBodyModel(BaseModel):
    description: Optional[str] = None
    required: bool = False
    content: Dict[str, MediaTypeModel]


class ResponseModel(BaseModel):
    description: Optional[str] = None
    content: Optional[Dict[str, MediaTypeModel]] = None


class SecuritySchemeModel(BaseModel):
    """Model representing an OpenAPI 3.x security scheme."""
    model_config = ConfigDict(populate_by_name=True)

    type: str  # e.g. "http", "apiKey", "oauth2", "openIdConnect"
    scheme: Optional[str] = None  # for http: "bearer", "basic", etc.
    bearer_format: Optional[str] = Field(default=None, alias="bearerFormat")
    name: Optional[str] = None  # for apiKey: name of header, query parameter, or cookie
    in_location: Optional[str] = Field(default=None, alias="in")  # "header", "query", "cookie"
    description: Optional[str] = None

    @model_validator(mode="after")
    def _normalize_fields(self) -> "SecuritySchemeModel":
        if self.scheme:
            self.scheme = self.scheme.lower()
        if self.in_location:
            self.in_location = self.in_location.lower()
        if self.type:
            self.type = self.type.lower()
        return self

    @property
    def location(self) -> Optional[str]:
        return self.in_location


class ResolvedSecurityRequirement(BaseModel):
    """Model representing a resolved security requirement for an endpoint."""
    model_config = ConfigDict(populate_by_name=True)

    scheme_name: Optional[str] = None
    scheme: Optional[SecuritySchemeModel] = None
    scopes: List[str] = Field(default_factory=list)
    schemes: Dict[str, SecuritySchemeModel] = Field(default_factory=dict)
    scopes_by_scheme: Dict[str, List[str]] = Field(default_factory=dict)

    @property
    def type(self) -> Optional[str]:
        return self.scheme.type if self.scheme else None

    @property
    def http_scheme(self) -> Optional[str]:
        return self.scheme.scheme if self.scheme else None

    @property
    def in_location(self) -> Optional[str]:
        return self.scheme.in_location if self.scheme else None

    @property
    def parameter_name(self) -> Optional[str]:
        return self.scheme.name if self.scheme else None


class EndpointModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    path: str
    method: str
    operation_id: Optional[str] = None
    summary: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    parameters: List[ParameterModel] = []
    request_body: Optional[RequestBodyModel] = None
    responses: Dict[str, ResponseModel]
    security: Optional[List[Dict[str, List[Any]]]] = None
    security_schemes: Optional[Dict[str, SecuritySchemeModel]] = None
    global_security: Optional[List[Dict[str, List[Any]]]] = None
    effective_security: Optional[List[ResolvedSecurityRequirement]] = None
    resolved_security: Optional[List[ResolvedSecurityRequirement]] = None

    @model_validator(mode="before")
    @classmethod
    def _sync_security_fields(cls, values: Any) -> Any:
        if isinstance(values, dict):
            if "effective_security" in values and "resolved_security" not in values:
                values["resolved_security"] = values["effective_security"]
            elif "resolved_security" in values and "effective_security" not in values:
                values["effective_security"] = values["resolved_security"]
        return values


class ParsedOpenAPISpec(BaseModel):
    """Complete container for a parsed OpenAPI 3.x specification."""
    model_config = ConfigDict(populate_by_name=True)

    openapi_version: str
    endpoints: List[EndpointModel]
    security_schemes: Dict[str, SecuritySchemeModel] = Field(default_factory=dict)
    global_security: Optional[List[Dict[str, List[Any]]]] = None


def _load_file(file_path: str) -> Dict[str, Any]:
    """Load a JSON or YAML OpenAPI file.

    Args:
        file_path: Path to the specification file.

    Returns:
        Parsed OpenAPI document as a dictionary.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: For unsupported extensions or files larger than ``MAX_SPEC_SIZE``.
        json.JSONDecodeError / yaml.YAMLError: For malformed contents.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Specification file not found: {file_path}")
    if path.stat().st_size > MAX_SPEC_SIZE:
        raise ValueError("Specification file exceeds maximum allowed size of 5 MB")

    ext = path.suffix.lower()
    raw = path.read_text(encoding="utf-8")
    if ext == ".json":
        return json.loads(raw)
    if ext in {".yaml", ".yml"}:
        return yaml.safe_load(raw) or {}
    raise ValueError("Unsupported file type. Only .json, .yaml, .yml are allowed.")


def _resolve_ref(ref: str, spec: Dict[str, Any]) -> Any:
    """Resolve a local reference within the OpenAPI specification.

    Only local references starting with ``#/components/`` are supported.
    """
    if not ref.startswith("#/components/"):
        raise ValueError(f"Unsupported $ref encountered: {ref}")
    parts = ref.lstrip("#/").split('/')
    try:
        obj = spec
        for p in parts:
            obj = obj[p]
        return obj
    except KeyError as exc:
        raise ValueError(f"Unresolved local reference: {ref}") from exc


def _collect_parameters(
    path_item: Dict[str, Any], operation: Dict[str, Any], spec: Dict[str, Any]
) -> List[ParameterModel]:
    merged: Dict[tuple, ParameterModel] = {}
    # Path‑level parameters first, then operation‑level (operation overrides if same name/location)
    for source in (path_item.get("parameters", []), operation.get("parameters", [])):
        for raw_param in source:
            if "$ref" in raw_param:
                raw_param = _resolve_ref(raw_param["$ref"], spec)
            try:
                param = ParameterModel(**raw_param)
                merged[(param.name, param.location)] = param
            except ValidationError as exc:
                raise ValueError(f"Invalid parameter definition: {raw_param}") from exc
    return list(merged.values())


def parse_security_schemes(spec: Dict[str, Any]) -> Dict[str, SecuritySchemeModel]:
    """Extract and validate security schemes defined in components.securitySchemes."""
    components = spec.get("components")
    if not isinstance(components, dict):
        return {}
    raw_schemes = components.get("securitySchemes", {})
    if not isinstance(raw_schemes, dict):
        return {}

    schemes: Dict[str, SecuritySchemeModel] = {}
    for name, raw_scheme in raw_schemes.items():
        if isinstance(raw_scheme, dict) and "$ref" in raw_scheme:
            raw_scheme = _resolve_ref(raw_scheme["$ref"], spec)
        if not isinstance(raw_scheme, dict):
            raise ValueError(f"Invalid security scheme definition for '{name}': must be a dictionary.")
        try:
            schemes[name] = SecuritySchemeModel(**raw_scheme)
        except ValidationError as exc:
            raise ValueError(f"Invalid security scheme definition for '{name}': {exc}") from exc
    return schemes


def _collect_security(
    operation: Dict[str, Any], global_security: Optional[List[Dict[str, List[Any]]]]
) -> Optional[List[Dict[str, List[Any]]]]:
    if "security" in operation:
        # Empty list means explicitly no security
        return operation["security"]
    return global_security


def _resolve_security(
    raw_security: Optional[List[Dict[str, List[Any]]]],
    security_schemes: Dict[str, SecuritySchemeModel],
) -> Optional[List[ResolvedSecurityRequirement]]:
    """Resolve security requirement names against parsed security schemes."""
    if raw_security is None:
        return None
    if len(raw_security) == 0:
        return []

    resolved: List[ResolvedSecurityRequirement] = []
    for req_item in raw_security:
        if not isinstance(req_item, dict):
            raise ValueError(f"Invalid security requirement item: {req_item}")

        req_schemes: Dict[str, SecuritySchemeModel] = {}
        scopes_by_scheme: Dict[str, List[str]] = {}
        for scheme_name, scopes in req_item.items():
            if scheme_name not in security_schemes:
                raise ValueError(
                    f"Security scheme '{scheme_name}' referenced in security requirement is not defined in components.securitySchemes."
                )
            req_schemes[scheme_name] = security_schemes[scheme_name]
            scopes_by_scheme[scheme_name] = [str(s) for s in scopes] if isinstance(scopes, list) else []

        first_name = list(req_item.keys())[0] if req_item else None
        first_scheme = req_schemes.get(first_name) if first_name else None
        first_scopes = scopes_by_scheme.get(first_name, []) if first_name else []

        resolved.append(
            ResolvedSecurityRequirement(
                scheme_name=first_name,
                scheme=first_scheme,
                scopes=first_scopes,
                schemes=req_schemes,
                scopes_by_scheme=scopes_by_scheme,
            )
        )
    return resolved


def parse_openapi_spec(file_path: str) -> ParsedOpenAPISpec:
    """Parse an OpenAPI 3.x file and return a complete :class:`ParsedOpenAPISpec` container."""
    spec = _load_file(file_path)
    version = spec.get("openapi") or spec.get("swagger")
    if not isinstance(version, str) or not version.startswith("3"):
        raise ValueError("Only OpenAPI 3.x specifications are supported.")

    security_schemes = parse_security_schemes(spec)
    global_security = spec.get("security")

    paths = spec.get("paths")
    if not isinstance(paths, dict):
        raise ValueError("Invalid OpenAPI document: missing or malformed 'paths' object.")

    endpoints: List[EndpointModel] = []

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in SUPPORTED_METHODS:
                continue
            if not isinstance(operation, dict):
                continue
            # Collect parameters (path‑level + operation‑level)
            params = _collect_parameters(path_item, operation, spec)
            # Request body (optional)
            request_body: Optional[RequestBodyModel] = None
            if "requestBody" in operation:
                raw_rb = operation["requestBody"]
                if isinstance(raw_rb, dict) and "$ref" in raw_rb:
                    raw_rb = _resolve_ref(raw_rb["$ref"], spec)
                try:
                    request_body = RequestBodyModel(**raw_rb)
                except ValidationError as exc:
                    raise ValueError("Invalid requestBody definition") from exc
            # Responses
            raw_resps = operation.get("responses", {})
            if not isinstance(raw_resps, dict):
                raise ValueError("Responses must be a mapping.")
            responses: Dict[str, ResponseModel] = {}
            for status, resp in raw_resps.items():
                if isinstance(resp, dict) and "$ref" in resp:
                    resp = _resolve_ref(resp["$ref"], spec)
                try:
                    responses[status] = ResponseModel(**resp)
                except ValidationError as exc:
                    raise ValueError(f"Invalid response definition for status {status}") from exc

            raw_sec = _collect_security(operation, global_security)
            effective_sec = _resolve_security(raw_sec, security_schemes)

            endpoint = EndpointModel(
                path=path,
                method=method.lower(),
                operation_id=operation.get("operationId"),
                summary=operation.get("summary"),
                description=operation.get("description"),
                tags=operation.get("tags"),
                parameters=params,
                request_body=request_body,
                responses=responses,
                security=raw_sec,
                security_schemes=security_schemes,
                global_security=global_security,
                effective_security=effective_sec,
                resolved_security=effective_sec,
            )
            endpoints.append(endpoint)

    return ParsedOpenAPISpec(
        openapi_version=version,
        endpoints=endpoints,
        security_schemes=security_schemes,
        global_security=global_security,
    )


def parse_openapi(file_path: str) -> List[EndpointModel]:
    """Parse an OpenAPI 3.x file and return a list of :class:`EndpointModel`.

    The function performs only local reference resolution and does not validate the
    full OpenAPI schema. Errors are raised as ``ValueError`` with an explanatory
    message.
    """
    return parse_openapi_spec(file_path).endpoints
