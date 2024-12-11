from .Templete import LLMClientTemplate
from .config import ANTHROPIC_MODEL
import aisuite as ai
class AnthropicClient(LLMClientTemplate):
    def __init__(self, api_key: str):
        super().__init__(api_key)
    def _initialize_client(self): 
        self.client = ai.Client({"anthropic": {"api_key": self.api_key}})
        self.model =ANTHROPIC_MODEL
        