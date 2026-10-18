"""Inbound evaluation pipeline exports."""
from .normalize import InputLimitError, NormalizedInput, normalize_inbound
from .rules import RuleEngine, RuleMatch
from .scoring import score_risk

__all__ = [
    "NormalizedInput", "InputLimitError", "normalize_inbound", "RuleEngine", "RuleMatch",
    "score_risk", "LLMClient", "NullLLMClient", "OpenAICompatibleLLMClient",
    "build_llm_client", "EvaluationService", "EvaluationResult",
]


def __getattr__(name):
    if name in {"LLMClient", "NullLLMClient", "OpenAICompatibleLLMClient", "build_llm_client"}:
        from .llm import LLMClient, NullLLMClient, OpenAICompatibleLLMClient, build_llm_client
        return locals()[name]
    if name in {"EvaluationService", "EvaluationResult"}:
        from .service import EvaluationResult, EvaluationService
        return locals()[name]
    raise AttributeError(name)
