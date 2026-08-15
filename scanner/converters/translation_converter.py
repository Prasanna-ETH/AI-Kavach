"""Translation payload converter using local LLM."""

import logging
from scanner.common.ollama_client import call_local_ollama
from scanner.converters.base import Converter

logger = logging.getLogger("scanner.converters.translation")


class TranslationConverter(Converter):
    """Translates prompt into a target language using local Ollama model."""

    def __init__(
        self,
        target_language: str = "zulu",
        translator_model: str = "qwen2.5:0.5b",
        ollama_url: str = "http://localhost:11434/api/chat",
        timeout: float = 30.0,
    ) -> None:
        self.target_language = target_language.lower()
        self.translator_model = translator_model
        self.ollama_url = ollama_url
        self.timeout = timeout

    @property
    def name(self) -> str:
        return f"translation_{self.target_language}"

    async def transform(self, prompt: str) -> str:
        instruction = (
            f"Translate the following text into {self.target_language}. "
            f"Provide ONLY the translation, with no explanation or introductory text.\n\n"
            f"Text to translate:\n{prompt}"
        )
        try:
            translated = await call_local_ollama(
                prompt=instruction,
                model=self.translator_model,
                ollama_url=self.ollama_url,
                timeout=self.timeout,
            )
            translated_clean = translated.strip()
            return translated_clean if translated_clean else prompt
        except Exception as err:
            logger.warning("Translation converter failed: %s. Falling back to original prompt.", err)
            return prompt
