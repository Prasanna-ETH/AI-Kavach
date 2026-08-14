"""Abstract Base Adapter interface for endpoint communication."""

from abc import ABC, abstractmethod


class BaseAdapter(ABC):
    """Abstract adapter defining standard send interface for target endpoints."""

    @abstractmethod
    async def send(self, prompt: str) -> str:
        """Send a prompt to the target LLM endpoint asynchronously and return response text.

        Args:
            prompt: The payload prompt to send.

        Returns:
            Extracted text response from the model.

        Raises:
            httpx.HTTPStatusError: On 4xx/5xx HTTP responses.
            httpx.RequestError: On network or connection failures.
            ValueError: On response parsing failures.
        """
        pass
