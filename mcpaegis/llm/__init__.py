"""Optional LLM client and prompt templates for semantic stages."""

from mcpaegis.llm.client import LLMClient, LLMUnavailable
from mcpaegis.llm.prompts import (
    PromptPair,
    build_metadata_semantic_prompt,
    build_post_exec_prompt,
    build_pre_exec_prompt,
)

__all__ = [
    "LLMClient",
    "LLMUnavailable",
    "PromptPair",
    "build_metadata_semantic_prompt",
    "build_post_exec_prompt",
    "build_pre_exec_prompt",
]
