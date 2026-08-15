"""Abstract base class for payload prompt converters."""

from abc import ABC, abstractmethod


class Converter(ABC):
    """Abstract base class for payload prompt converters."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier/name of the converter (e.g. 'base64', 'leetspeak', 'translation_zulu')."""
        pass

    @abstractmethod
    async def transform(self, prompt: str) -> str:
        """Transform prompt text into an encoded/obfuscated variant.

        Args:
            prompt: Original prompt text.

        Returns:
            Transformed prompt text.
        """
        pass
