"""Base64 payload converter."""

import base64
from scanner.converters.base import Converter


class Base64Converter(Converter):
    """Encodes prompt using standard base64 encoding."""

    @property
    def name(self) -> str:
        return "base64"

    async def transform(self, prompt: str) -> str:
        return base64.b64encode(prompt.encode("utf-8")).decode("utf-8")
