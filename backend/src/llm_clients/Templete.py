from abc import ABC, abstractmethod
from .config import SystemContent
from .llm_base import LLMClientBase, MessagePassingInterface
from .exceptions import ClientException, MessageValidationError, MessageFormatError, TextGenerationError
import aisuite as ai
from sentry_sdk import capture_exception
from ..logger.base import logger

system_content=SystemContent()

class LLMClientTemplate(LLMClientBase, ABC):
    
    def __init__(self,api_key:str):
        self.api_key=api_key
        self._initialize_client()

    @abstractmethod
    def _initialize_client(self):        
        pass
    
    def evaluate_relevance(self, title):
        try:
            messages=system_content.MESSAGES_FOR_RELEVANCE
            ai_info=self._generate_MPI_dict(messages, title)
            return self._generate_text(messages=ai_info)
        except Exception as e:
            logger.error(f"Failed to evaluate relevance: {str(e)}")
            capture_exception(e)
            raise TextGenerationError(f"Failed to evaluate relevance: {str(e)}")

    def generate_summary(self, content):
        try:
            messages=system_content.MESSAGES_FOR_GENERATE_SUMMARY
            ai_info=self._generate_MPI_dict(messages, content)
            return self._generate_text(messages=ai_info)
        except Exception as e:
            logger.error(f"Failed to generate summary: {str(e)}")
            capture_exception(e)
            raise TextGenerationError(f"Failed to generate summary: {str(e)}")

    def extract_search_keywords(self,content):
        try:
            messages=system_content.MESSAGES_FOR_KEYWORDS
            ai_info=self._generate_MPI_dict(messages, content)
            return self._generate_text(messages=ai_info)
        except Exception as e:
            logger.error(f"Failed to extract keywords: {str(e)}")
            capture_exception(e)
            raise TextGenerationError(f"Failed to extract keywords: {str(e)}")
 
    def _generate_text(self,messages):
        try:
            completion = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
            )
            return completion.choices[0].message.content
        except Exception as e:
            logger.error(f"Failed to generate text: {str(e)}")
            capture_exception(e)
            raise TextGenerationError(f"Failed to generate text: {str(e)}")

    def _generate_MPI_dict(self, system_content, user_content):
        try:
            mpi = MessagePassingInterface(system_content=system_content, user_content=user_content)
            return mpi.to_dict
        except (MessageValidationError, MessageFormatError) as e:
            logger.error(f"Message format validation failed: {str(e)}")
            capture_exception(e)
            raise e
        except Exception as e:
            logger.error(f"Failed to generate message format: {str(e)}")
            capture_exception(e)
            raise TextGenerationError(f"Failed to generate message format: {str(e)}")
