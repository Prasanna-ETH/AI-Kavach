"""Leetspeak payload converter."""

from scanner.converters.base import Converter


class LeetspeakConverter(Converter):
    """Replaces common letters with leetspeak equivalents (a->4, e->3, i->1, o->0, s->5, t->7)."""

    LEET_MAP = {
        'a': '4', 'A': '4',
        'e': '3', 'E': '3',
        'i': '1', 'I': '1',
        'o': '0', 'O': '0',
        's': '5', 'S': '5',
        't': '7', 'T': '7',
    }

    @property
    def name(self) -> str:
        return "leetspeak"

    async def transform(self, prompt: str) -> str:
        return "".join(self.LEET_MAP.get(ch, ch) for ch in prompt)
