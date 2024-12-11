from .Templete import LLMClientTemplate
from .config import GPT_MODEL
import aisuite as ai
class OpenAIClient(LLMClientTemplate):
    def __init__(self, api_key: str):
        super().__init__(api_key)
    def _initialize_client(self): 
        self.client = ai.Client({"openai": {"api_key": self.api_key}})
        self.model =GPT_MODEL      








