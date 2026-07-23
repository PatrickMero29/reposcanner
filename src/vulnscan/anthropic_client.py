"""Thin wrapper around the Anthropic API for structured-output calls with retries.

Claude doesn't have a native `response_schema` parameter the way Gemini's
structured-output mode does. Instead, structured output is obtained via
*forced tool use*: the target Pydantic schema is exposed to Claude as a
single tool, `tool_choice` forces Claude to call that tool, and the tool
call's `input` dict is what we validate back into the Pydantic model. This
is the standard pattern for extracting structured data from Claude, and it
means every call here always returns a schema-valid object or raises.
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import TypeVar

import anthropic
from pydantic import BaseModel

from .config import require_api_key, settings

logger = logging.getLogger("vulnscan.anthropic")

T = TypeVar("T", bound=BaseModel)

_client: anthropic.AsyncAnthropic | None = None

_TOOL_NAME = "record_result"


def get_client() -> anthropic.AsyncAnthropic:
    global _client
    if _client is None:
        _client = anthropic.AsyncAnthropic(api_key=require_api_key())
    return _client


def _schema_to_tool(response_schema: type[BaseModel]) -> dict:
    """Turn a Pydantic model into an Anthropic tool definition whose
    input_schema exactly matches the model (including nested $defs)."""
    schema = response_schema.model_json_schema()
    schema.pop("title", None)  # redundant — the tool name already conveys this
    return {
        "name": _TOOL_NAME,
        "description": f"Record the result as a {response_schema.__name__} object.",
        "input_schema": schema,
    }


def _retry_after_seconds(exc: Exception) -> float | None:
    """Anthropic rate-limit errors carry a Retry-After header — prefer that
    exact wait over guessing with exponential backoff when it's present."""
    response = getattr(exc, "response", None)
    if response is None:
        return None
    try:
        retry_after = response.headers.get("retry-after")
        return float(retry_after) if retry_after is not None else None
    except (ValueError, AttributeError):
        return None


async def generate_structured(
    *,
    prompt: str,
    response_schema: type[T],
    model: str | None = None,
    temperature: float | None = None,
    max_tokens: int | None = None,
) -> T:
    """Call Claude and parse the forced tool-use response into `response_schema`.

    Retries with exponential backoff (or the server-provided Retry-After,
    when available) on rate limits and transient API/connection errors.
    Raises the last exception if all retries are exhausted so callers can
    decide how to account for the failure.
    """
    client = get_client()
    model = model or settings.analyzer_model
    temperature = settings.temperature if temperature is None else temperature
    max_tokens = max_tokens or settings.max_output_tokens
    tool = _schema_to_tool(response_schema)

    last_exc: Exception | None = None
    for attempt in range(settings.max_retries):
        try:
            response = await client.messages.create(
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
                tools=[tool],
                tool_choice={"type": "tool", "name": _TOOL_NAME},
                messages=[{"role": "user", "content": prompt}],
            )
            
            for block in response.content:
                if block.type == "tool_use" and block.name == _TOOL_NAME:
                    return response_schema.model_validate(block.input)
            raise ValueError(f"No tool_use block found in Claude's response: {response.content!r}")
        
        except anthropic.BadRequestError as exc:
            # 400s are not transient — retrying the exact same malformed/
            # unpayable request will never succeed (e.g. "credit balance too
            # low", invalid schema, etc). Fail immediately with a clear error
            # instead of burning the retry budget.
            logger.error("Claude rejected the request (non-retryable): %s", exc)
            raise

        except (anthropic.RateLimitError, anthropic.APIStatusError, anthropic.APIConnectionError) as exc:
            last_exc = exc
            wait = _retry_after_seconds(exc) or min(30.0, (2 ** attempt) + random.uniform(0, 1))
            logger.warning(
                "Claude call failed (attempt %d/%d): %s — retrying in %.1fs",
                attempt + 1, settings.max_retries, exc, wait,
            )
            await asyncio.sleep(wait)

        except Exception as exc:  # noqa: BLE001 — e.g. a tool-input validation failure
            last_exc = exc
            wait = min(30.0, (2 ** attempt) + random.uniform(0, 1))
            logger.warning(
                "Unexpected error calling Claude (attempt %d/%d): %s — retrying in %.1fs",
                attempt + 1, settings.max_retries, exc, wait,
            )
            await asyncio.sleep(wait)

    assert last_exc is not None
    raise last_exc
