from .Templete import LLMClientTemplate
from .config import GPT_MODEL
from ..logger.base import logger

class OpenAIClient(LLMClientTemplate):
    def _initialize_client(self):
        super()._initialize_client("openai", GPT_MODEL)
        self.model = GPT_MODEL
