import abc
import aisuite as ai
from ..logger.base import logger

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
        return NotImplemented

    @abc.abstractmethod
    def extract_search_keywords(self, news_expectation: str) -> str | None:
        raise NotImplementedError


    @abc.abstractmethod
    def evaluate_relevance(self, title: str) ->str:
        raise NotImplementedError
    
    @abc.abstractmethod
    def generate_summary(self, content) ->str:
        raise NotImplementedError