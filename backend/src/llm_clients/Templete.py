from abc import ABC, abstractmethod
from .config import SystemContent
from .llm_base import LLMClientBase
from .exceptions import MessageFormatError, TextGenerationError
from sentry_sdk import capture_exception
from ..logger.base import logger
import aisuite as ai
system_content=SystemContent()

class LLMClientTemplate(LLMClientBase, ABC):
    
    def __init__(self,api_key:str):
        self.api_key=api_key
        self._initialize_client()
        logger.info("LLM client template initialized")
        
    @abstractmethod
    def _initialize_client(self, model_name: str, key_name: str):
        self.client = ai.Client({model_name: {"api_key": self.api_key}})

    def evaluate_relevance(self, title):
        try:
            messages=system_content.MESSAGES_FOR_RELEVANCE
            result = self._generate_text(messages,title)
            logger.info(f"Successfully evaluated relevance for title: {title}")
            return result
        except Exception as e:
            logger.error(f"Failed to evaluate relevance for title {title}: {str(e)}")
            capture_exception(e)
            raise

    def generate_summary(self, content):
        try:
            messages=system_content.MESSAGES_FOR_GENERATE_SUMMARY
            result = self._generate_text(messages,content)
            logger.info("Successfully generated summary")
            return result
        except Exception as e:
            logger.error(f"Failed to generate summary: {str(e)}")
            capture_exception(e)
            raise

    def extract_search_keywords(self,content):
        try:
            messages=system_content.MESSAGES_FOR_KEYWORDS
            result = self._generate_text(messages,content)
            logger.info("Successfully extracted search keywords")
            return result
        except Exception as e:
            logger.error(f"Failed to extract search keywords: {str(e)}")
            capture_exception(e)
            raise
 
    def _generate_text(self,system_content,user_content):
        try:
            completion = self.client.chat.completions.create(
                model=self.model,
                messages=self._llm_messages(system_content, user_content)
            )
            logger.info("Successfully generated text response")
            return completion.choices[0].message.content
        except Exception as e:
            logger.error(f"Failed to generate text: {str(e)}")
            capture_exception(e)
            raise TextGenerationError(f"Failed to generate text: {str(e)}")

    def _llm_messages(self, system_content: str, user_content: str) -> list:
        try:
            if system_content is None or user_content is None:
                raise MessageFormatError("系統內容或使用者內容不能為空")
            messages = [
                {"role": "system", "content": system_content},
                {"role": "user", "content": user_content}
            ]
            logger.debug("Successfully formatted LLM messages")
            return messages
        except Exception as e:
            logger.error(f"Failed to format LLM messages: {str(e)}")
            capture_exception(e)
            raise MessageFormatError(f"Failed to format messages: {str(e)}")
