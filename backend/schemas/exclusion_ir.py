"""Strict intermediate representation for telemetry noise exclusions."""

from typing import List, Literal, Union

try:
    from pydantic import BaseModel, Field, ConfigDict
except ImportError:  # Keep lightweight unit-test imports functional without backend deps.
    class BaseModel:
        def __init__(self, **values):
            annotations = getattr(self.__class__, "__annotations__", {})
            for name in annotations:
                if name in values:
                    setattr(self, name, values[name])
                elif hasattr(self.__class__, name):
                    setattr(self, name, getattr(self.__class__, name))

        @classmethod
        def model_validate(cls, value):
            required = {
                "SingleFieldExclusion": ("field", "values"),
                "CompoundCondition": ("field", "operator", "value"),
                "CompoundExclusion": ("conditions",),
                "RuleTuningAnalysis": ("noise_summary", "recommended_threshold"),
            }.get(cls.__name__, ())
            missing = [name for name in required if name not in value]
            if missing:
                raise ValueError(f"Missing required fields: {', '.join(missing)}")
            return cls(**value)

        @classmethod
        def model_json_schema(cls):
            return {"title": cls.__name__, "type": "object"}

    def Field(default=None, **kwargs):
        return None if default is ... else default

    def ConfigDict(**kwargs):
        return kwargs


class SingleFieldExclusion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["single_field"] = "single_field"
    field: str = Field(..., min_length=1)
    operator: Literal["!in", "==", "!="] = "!in"
    values: List[str] = Field(..., min_length=1)


class CompoundCondition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: str = Field(..., min_length=1)
    operator: Literal["==", "!=", "has", "contains"]
    value: str = Field(..., min_length=1)


class CompoundExclusion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["compound"] = "compound"
    conditions: List[CompoundCondition] = Field(..., min_length=2)


class RuleTuningAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    noise_summary: str = Field(..., min_length=1)
    recommended_threshold: int
    exclusions: List[Union[SingleFieldExclusion, CompoundExclusion]] = Field(
        default_factory=list
    )
