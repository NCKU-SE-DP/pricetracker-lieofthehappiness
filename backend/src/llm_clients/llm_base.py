import abc
import logging
from sentry_sdk import capture_exception
from pydantic import BaseModel, Field
import aisuite as ai
from .exceptions import MessageValidationError, MessageFormatError
from ..logger.base import logger

class MessagePassingInterface(BaseModel):
    system_content: str = Field(...)
    user_content: str = Field(...)

    @property
    def to_dict(self) -> list[dict[str, str]]:
        try:
            if not self.system_content or not self.user_content:
                raise MessageValidationError("System content or user content cannot be empty")
            
            dicts = [
                {"role": "system", "content": f"{self.system_content}"},
                {"role": "user", "content": f"{self.user_content}"}
            ]
            return dicts
        except Exception as e:
            logger.error(f"Error in message format conversion: {str(e)}")
            capture_exception(e)
            raise MessageFormatError(f"Error occurred while converting message format: {str(e)}")



class LLMClientBase(metaclass=abc.ABCMeta):
    client: ai.Client = ...
    @abc.abstractmethod
    def _generate_text(self,messages:dict) -> str:
        """
        Generate the response based on the system and user content.
        :param system_content: 
        :param user_content: 
        :return: 
        """
        try:
            return NotImplemented
        except Exception as e:
            logger.error(f"Error in text generation: {str(e)}")
            capture_exception(e)
            raise

    @abc.abstractmethod
    def extract_search_keywords(self, news_expectation: str) -> str | None:
        try:
            raise NotImplementedError
        except Exception as e:
            logger.error(f"Error in keyword extraction: {str(e)}")
            capture_exception(e)
            raise


    @abc.abstractmethod
    def evaluate_relevance(self, title: str) ->str:
        try:
            raise NotImplementedError
        except Exception as e:
            logger.error(f"Error in relevance evaluation: {str(e)}")
            capture_exception(e)
            raise
    
    @abc.abstractmethod
    def generate_summary(self, content) ->str:
        try:
            raise NotImplementedError
        except Exception as e:
            logger.error(f"Error in summary generation: {str(e)}")
            capture_exception(e)
            raise