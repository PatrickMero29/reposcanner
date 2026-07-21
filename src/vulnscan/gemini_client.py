"""Thin wrapper around google-genai for structured-output calls with retries."""

from __future__ import annotations

import asyncio
import logging
import random
from typing import TypeVar

from google import genai
from google.genai import types
from pydantic import BaseModel

from .config import require_api_key, settings

logger = logging.getLogger("vulnscan.gemini")

T = TypeVar("T", bound=BaseModel)

_client: genai.Client | None = None


def get_client() -> genai.Client:
    global _client
    if _client is None:
        _client = genai.Client(api_key=require_api_key())
    return _client


async def generate_structured(
    *,
    prompt: str,
    response_schema: type[T],
    model: str | None = None,
    temperature: float | None = None,
) -> T:
    """Call Gemini and parse the response into `response_schema`.

    Retries with exponential backoff + jitter on transient errors. Raises the
    last exception if all retries are exhausted so callers can decide how to
    account for the failure (e.g. mark the function as "analysis failed"
    rather than silently reporting zero vulnerabilities).
    """
    client = get_client()
    model = model or settings.analyzer_model
    temperature = settings.temperature if temperature is None else temperature

    config = types.GenerateContentConfig(
        response_mime_type="application/json",
        response_schema=response_schema,
        temperature=temperature,
        max_output_tokens=settings.max_output_tokens,
    )

    last_exc: Exception | None = None
    for attempt in range(settings.max_retries):
        try:
            response = await client.aio.models.generate_content(
                model=model,
                contents=prompt,
                config=config,
            )
            parsed = response.parsed
            if parsed is None:
                raise ValueError(f"Gemini returned no parseable output (finish_reason issue?): {response.text[:500]!r}")
            return parsed
        except Exception as exc:  # noqa: BLE001 - deliberately broad, we classify by retrying
            last_exc = exc
            wait = min(30.0, (2 ** attempt) + random.uniform(0, 1))
            logger.warning(
                "Gemini call failed (attempt %d/%d): %s — retrying in %.1fs",
                attempt + 1, settings.max_retries, exc, wait,
            )
            await asyncio.sleep(wait)

    assert last_exc is not None
    raise last_exc
