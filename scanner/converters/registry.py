"""Registry and factory for converters."""

from typing import Dict, Type
from scanner.converters.base import Converter
from scanner.converters.base64_converter import Base64Converter
from scanner.converters.leetspeak_converter import LeetspeakConverter
from scanner.converters.rot13_converter import Rot13Converter
from scanner.converters.roleplay_converter import RoleplayConverter
from scanner.converters.composite_converter import CompositeBase64Converter
from scanner.converters.translation_converter import TranslationConverter

BUILTIN_CONVERTERS: Dict[str, Type[Converter]] = {
    "base64": Base64Converter,
    "leetspeak": LeetspeakConverter,
    "rot13": Rot13Converter,
    "roleplay": RoleplayConverter,
    "composite_b64": CompositeBase64Converter,
    "composite": CompositeBase64Converter,
}


def get_converter(name: str, **kwargs) -> Converter:
    """Factory function mapping converter name to a Converter instance.

    Args:
        name: Name of converter, e.g. "base64", "leetspeak", "rot13", "translation_zulu", or "translation".
        **kwargs: Optional keyword arguments passed to converter constructor.

    Returns:
        Converter instance.

    Raises:
        ValueError: If unknown converter name is requested.
    """
    clean_name = name.strip().lower()

    if clean_name in BUILTIN_CONVERTERS:
        return BUILTIN_CONVERTERS[clean_name](**kwargs)

    if clean_name.startswith("translation_"):
        target_lang = clean_name.split("translation_", 1)[1]
        return TranslationConverter(target_language=target_lang, **kwargs)

    if clean_name == "translation":
        return TranslationConverter(**kwargs)

    available = list(BUILTIN_CONVERTERS.keys()) + ["translation_<language>", "translation"]
    raise ValueError(
        f"Unknown converter '{name}'. Available converters: {', '.join(available)}"
    )
