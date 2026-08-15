"""ROT13 payload converter."""

import codecs
from scanner.converters.base import Converter


class Rot13Converter(Converter):
    """Encodes prompt using ROT13 cipher."""

    @property
    def name(self) -> str:
        return "rot13"

    async def transform(self, prompt: str) -> str:
        return codecs.encode(prompt, "rot13")
