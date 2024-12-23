from .Templete import LLMClientTemplate
from .config import ANTHROPIC_MODEL
import aisuite as ai
from .exceptions import ClientException
from ..logger.base import logger
from sentry_sdk import capture_exception


class AnthropicClient(LLMClientTemplate):
    def __init__(self, api_key: str):
        super().__init__(api_key)
        logger.info("Initializing Anthropic client")
        
    def _initialize_client(self):
        try:
            self.client = ai.Client({"anthropic": {"api_key": self.api_key}})
            self.model = ANTHROPIC_MODEL
            logger.info("Successfully initialized Anthropic client")
        except Exception as e:
            logger.error(f"Failed to initialize Anthropic client: {str(e)}")
            capture_exception(e)
            raise ClientException(f"Failed to initialize client: {str(e)}")