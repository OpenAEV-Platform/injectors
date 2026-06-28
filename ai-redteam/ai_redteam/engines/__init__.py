"""Engine registry. Each engine implements one execution backend for AI red-team techniques."""

from ai_redteam.contracts import constants as c
from ai_redteam.engines.garak import GarakEngine
from ai_redteam.engines.native import NativeEngine
from ai_redteam.engines.promptfoo import PromptfooEngine
from ai_redteam.engines.pyrit import PyritEngine


def build_registry(timeout=120):
    return {
        c.ENGINE_NATIVE: NativeEngine(timeout=timeout),
        c.ENGINE_GARAK: GarakEngine(timeout=timeout),
        c.ENGINE_PYRIT: PyritEngine(timeout=timeout),
        c.ENGINE_PROMPTFOO: PromptfooEngine(timeout=timeout),
    }


# Map each contract id to the engine that should run it
def contract_engine_map():
    return {technique.contract_id: technique.engine for technique in c.ALL_TECHNIQUES}
