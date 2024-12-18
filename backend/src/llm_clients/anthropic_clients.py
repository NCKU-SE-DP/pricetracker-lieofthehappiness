from .Templete import LLMClientTemplate
from .config import ANTHROPIC_MODEL
import aisuite as ai
from .exceptions import ClientException
class AnthropicClient(LLMClientTemplate):
    def __init__(self, api_key: str):
        super().__init__(api_key)
        
    def _initialize_client(self):
        try:
            self.client = ai.Client({"anthropic": {"api_key": self.api_key}})
            self.model = ANTHROPIC_MODEL
        except Exception as e:
            raise ClientException(f"Failed to initialize client: {str(e)}")