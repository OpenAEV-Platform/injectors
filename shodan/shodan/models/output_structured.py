from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field, field_serializer, field_validator


class PlatformType(StrEnum):
    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"
    CONTAINER = "container"
    SERVICE = "service"
    GENERIC = "generic"
    INTERNAL = "internal"
    UNKNOWN = "unknown"

    @classmethod
    def from_string(cls, value: str | None) -> "PlatformType":
        if not isinstance(value, str) or not value.strip():
            return cls.UNKNOWN

        normalize_value = value.strip().lower()
        if normalize_value in cls._value2member_map_:
            return cls(normalize_value)
        else:
            return cls.UNKNOWN


class AssetExtendedAttributes(BaseModel):
    ip_addresses: list[str]
    platform: PlatformType = Field(default=PlatformType.UNKNOWN)
    hostname: str
    mac_addresses: list[str] = Field(default_factory=list)
    arch: str = Field(default="Unknown")
    end_of_life: bool = Field(default=False)

    @field_validator("platform", mode="before")
    @classmethod
    def normalize_platform(cls, value):
        return PlatformType.from_string(value)

    @field_serializer("platform")
    def capitalize_platform(self, value: PlatformType):
        return value.value.capitalize()


class Asset(BaseModel):
    name: str
    type: Literal["Endpoint"] = Field(default="Endpoint")
    description: str = Field(default="")
    external_reference: str = Field(default="")
    tags: list[str] = Field(default_factory=list)
    extended_attributes: AssetExtendedAttributes
