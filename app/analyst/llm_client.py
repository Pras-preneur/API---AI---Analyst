
"""NVIDIA Nemotron API client."""

import json
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from config import NVIDIA_API_KEY, NVIDIA_BASE_URL, NVIDIA_MODEL


class LLMClientError(Exception):
    """Raised when the LLM API request fails."""


def generate_llm_response(
    system_prompt: str,
    user_prompt: str,
    temperature: float = 0.2,
    max_tokens: int = 1200,
) -> str:
    """Send prompts to NVIDIA Nemotron and return its response."""

    if not NVIDIA_API_KEY:
        raise LLMClientError(
            "NVIDIA_API_KEY is not configured in the .env file."
        )

    if not NVIDIA_MODEL:
        raise LLMClientError(
            "NVIDIA_MODEL is not configured in the .env file."
        )

    url = f"{NVIDIA_BASE_URL}/chat/completions"

    payload = {
        "model": NVIDIA_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }

    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {NVIDIA_API_KEY}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urlopen(request, timeout=60) as response:
            result = json.loads(response.read().decode("utf-8"))

        content = result["choices"][0]["message"]["content"]

        if not isinstance(content, str) or not content.strip():
            raise LLMClientError("The LLM returned an empty response.")

        return content.strip()

    except HTTPError as exc:
        raise LLMClientError(
            f"NVIDIA API returned HTTP {exc.code}."
        ) from None

    except (URLError, TimeoutError) as exc:
        raise LLMClientError(
            f"Could not connect to NVIDIA API: {exc.reason if isinstance(exc, URLError) else 'Request timed out'}"
        ) from None

    except (json.JSONDecodeError, KeyError, IndexError, TypeError):
        raise LLMClientError(
            "NVIDIA API returned an invalid response."
        ) from None
