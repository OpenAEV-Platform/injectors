"""Resolves the AI target connection for an inject.

Two ways to specify the target:
  1. Reference an `AiTarget` asset by id (contract field `ai_target`) - fetched from the platform.
  2. Provide the connection inline on the inject (provider / endpoint / model / api key variable).

Secrets are never read from the platform: the credential is resolved from the injector process
environment using the variable name carried by the target (`api_key_variable`).
"""

import os

from ai_redteam.contracts import constants as c


class TargetConfig:
    def __init__(
        self,
        provider="OPENAI_COMPATIBLE",
        endpoint=None,
        model=None,
        modality="TEXT",
        system_prompt=None,
        api_key_variable=None,
        configuration=None,
    ):
        self.provider = (provider or "OPENAI_COMPATIBLE").upper()
        self.endpoint = endpoint
        self.model = model
        self.modality = modality or "TEXT"
        self.system_prompt = system_prompt
        self.api_key_variable = api_key_variable
        self.configuration = configuration or {}
        self.api_key = os.environ.get(api_key_variable) if api_key_variable else None


def _from_ai_target_asset(asset: dict) -> TargetConfig:
    return TargetConfig(
        provider=asset.get("ai_target_provider"),
        endpoint=asset.get("ai_target_endpoint"),
        model=asset.get("ai_target_model"),
        modality=asset.get("ai_target_modality", "TEXT"),
        system_prompt=asset.get("ai_target_system_prompt"),
        api_key_variable=asset.get("ai_target_api_key_variable"),
        configuration=asset.get("ai_target_configuration") or {},
    )


def _from_inline(content: dict) -> TargetConfig:
    return TargetConfig(
        provider=content.get(c.KEY_PROVIDER) or "OPENAI_COMPATIBLE",
        endpoint=content.get(c.KEY_ENDPOINT),
        model=content.get(c.KEY_MODEL),
        system_prompt=content.get(c.KEY_SYSTEM_PROMPT),
        api_key_variable=content.get(c.KEY_API_KEY_VAR),
    )


def resolve_target(content: dict, api, logger=None) -> TargetConfig:
    ai_target_id = content.get(c.KEY_TARGET_REF)
    if ai_target_id:
        try:
            asset = api.http_get(f"/ai_targets/{ai_target_id}")
            target = _from_ai_target_asset(asset)
            # Inline fields may still override the system prompt for a given inject
            if content.get(c.KEY_SYSTEM_PROMPT):
                target.system_prompt = content.get(c.KEY_SYSTEM_PROMPT)
            return target
        except Exception as exc:  # noqa: BLE001 - fall back to inline definition
            if logger:
                logger.warning(f"Could not fetch AI target {ai_target_id}: {exc}")
    return _from_inline(content)
