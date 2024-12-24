from .Templete import LLMClientTemplate
from .config import ANTHROPIC_MODEL
from ..logger.base import logger

class AnthropicClient(LLMClientTemplate):  
    def _initialize_client(self):
        super()._initialize_client("anthropic", ANTHROPIC_MODEL)
        self.model = ANTHROPIC_MODEL