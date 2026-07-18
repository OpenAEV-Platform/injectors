"""Resolves the AI target connection(s) for an inject.

The contract exposes a "Type of targets" selector (`target_selector`) with three modes:
  1. ``ai_target`` (default) - reference a pre-configured `AiTarget` asset by id (contract field
     `ai_target`), fetched from the platform.
  2. ``asset-groups`` - run the technique against every `AiTarget` asset that belongs to the
     selected asset group(s). The groups are carried on the injector message (`assetGroups`).
  3. ``manual`` - provide the connection inline on the inject (provider / endpoint / model /
     token / system prompt).

For backward compatibility, when no selector is present we keep the legacy behaviour: use the
`ai_target` reference if one is set, otherwise fall back to the inline definition.

The credential always comes from the AI target configuration (`ai_target_token`, or the inline
`target_token` in manual mode). It is optional: targets that require no authentication (e.g. a
local model deployment) simply carry no token. The injector never reads credentials from its own
environment or configuration.
"""

from ai_redteam.contracts import constants as c


class TargetConfig:
    def __init__(
        self,
        provider="OPENAI_COMPATIBLE",
        endpoint=None,
        model=None,
        modality="TEXT",
        system_prompt=None,
        configuration=None,
        name=None,
        asset_id=None,
        token=None,
    ):
        self.provider = (provider or "OPENAI_COMPATIBLE").upper()
        self.endpoint = endpoint
        self.model = model
        self.modality = modality or "TEXT"
        self.system_prompt = system_prompt
        self.configuration = configuration or {}
        # Optional credential carried by the target; empty (or whitespace-only)
        # means no authentication, so we normalise it to None to avoid sending a
        # meaningless "Bearer  " header.
        if isinstance(token, str):
            token = token.strip()
        self.token = token or None
        self.api_key = self.token
        # Optional identity (set when the target comes from an AiTarget asset), used for
        # multi-target execution messages and result correlation.
        self.name = name
        self.asset_id = asset_id


def _from_ai_target_asset(asset: dict) -> TargetConfig:
    return TargetConfig(
        provider=asset.get("ai_target_provider"),
        endpoint=asset.get("ai_target_endpoint"),
        model=asset.get("ai_target_model"),
        modality=asset.get("ai_target_modality", "TEXT"),
        system_prompt=asset.get("ai_target_system_prompt"),
        configuration=asset.get("ai_target_configuration") or {},
        name=asset.get("asset_name"),
        asset_id=asset.get("asset_id"),
        token=asset.get("ai_target_token"),
    )


def _from_inline(content: dict) -> TargetConfig:
    return TargetConfig(
        provider=content.get(c.KEY_PROVIDER) or "OPENAI_COMPATIBLE",
        endpoint=content.get(c.KEY_ENDPOINT),
        model=content.get(c.KEY_MODEL),
        system_prompt=content.get(c.KEY_SYSTEM_PROMPT),
        token=content.get(c.KEY_TOKEN),
    )


def _asset_group_ids(data: dict) -> list:
    groups = (data or {}).get(c.ASSET_GROUPS_KEY_RABBITMQ) or []
    return [g["asset_group_id"] for g in groups if g.get("asset_group_id")]


def _collect_ai_target_ids_in_group(group_id: str, api, logger=None) -> list:
    """Return the ids of every AI target that is a member of one asset group.

    Uses the asset-group members endpoint, which resolves BOTH static and dynamic
    membership across all asset types (an ``All AI Targets`` group with a
    ``Category = AI_TARGET`` dynamic rule has no static members, so a static-only
    membership filter would wrongly return nothing). Only AI targets are kept.
    """
    ids = []
    page = 0
    while True:
        body = {"page": page, "size": 100, "textSearch": ""}
        try:
            response = api.http_post(
                f"/asset_groups/{group_id}/assets/search", post_data=body
            )
        except Exception as exc:  # noqa: BLE001
            if logger:
                logger.warning(
                    f"Could not fetch assets for asset group {group_id}: {exc}"
                )
            break
        content = response.get("content") or []
        ids.extend(
            asset["asset_id"]
            for asset in content
            if asset.get("asset_category") == c.AI_TARGET_CATEGORY
            and asset.get("asset_id")
        )
        if response.get("last", True) or not content:
            break
        page += 1
    return ids


def _fetch_ai_targets_in_groups(group_ids: list, api, logger=None) -> list:
    """Resolve every AI target asset (static OR dynamic member) of the given group(s).

    The group-members endpoint only carries a summary of each asset (no connection
    fields), so each AI target is then loaded in full via ``/ai_targets/{id}``.
    """
    seen = set()
    ordered_ids = []
    for group_id in group_ids:
        for asset_id in _collect_ai_target_ids_in_group(group_id, api, logger):
            if asset_id not in seen:
                seen.add(asset_id)
                ordered_ids.append(asset_id)

    targets = []
    for asset_id in ordered_ids:
        try:
            asset = api.http_get(f"/ai_targets/{asset_id}")
            targets.append(_from_ai_target_asset(asset))
        except Exception as exc:  # noqa: BLE001
            if logger:
                logger.warning(f"Could not fetch AI target {asset_id}: {exc}")
    return targets


def _resolve_single(content: dict, api, logger=None) -> TargetConfig:
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


def resolve_target(content: dict, api, logger=None) -> TargetConfig:
    """Resolve a single target (ai_target / manual / legacy). Kept for backward compatibility."""
    selector = content.get(c.KEY_TARGET_SELECTOR)
    if selector == c.TARGET_SELECTOR_MANUAL:
        return _from_inline(content)
    return _resolve_single(content, api, logger)


def resolve_targets(content: dict, data: dict, api, logger=None) -> list:
    """Resolve every target for the inject as a list of TargetConfig (>= 1 in the happy path)."""
    selector = content.get(c.KEY_TARGET_SELECTOR)

    if selector == c.TARGET_SELECTOR_ASSET_GROUPS:
        group_ids = _asset_group_ids(data)
        if not group_ids:
            raise ValueError("No asset group selected for this AI red-team inject")
        targets = _fetch_ai_targets_in_groups(group_ids, api, logger)
        if not targets:
            raise ValueError(
                "The selected asset group(s) contain no AI target assets to test"
            )
        return targets

    if selector == c.TARGET_SELECTOR_MANUAL:
        return [_from_inline(content)]

    return [_resolve_single(content, api, logger)]
