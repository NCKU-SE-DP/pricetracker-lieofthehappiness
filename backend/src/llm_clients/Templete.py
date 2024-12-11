from abc import ABC, abstractmethod
from .config import SystemContent
from .llm_base import LLMClientBase, MessagePassingInterface
import aisuite as ai
system_content=SystemContent()


class LLMClientTemplate(LLMClientBase, ABC):


    
    def __init__(self,api_key:str):
        self.api_key=api_key
        self._initialize_client()
    @abstractmethod
    def _initialize_client(self):        
        pass
    
    def evaluate_relevance(self, title):
        messages=system_content.MESSAGES_FOR_RELEVANCE
        ai_info=self._generate_MPI(messages, title)
        return self._generate_text(messages=ai_info)

    def generate_summary(self, content):
        messages=system_content.MESSAGES_FOR_GENERATE_SUMMARY
        ai_info=self._generate_MPI(messages, content)
        return self._generate_text(messages=ai_info)

    def extract_search_keywords(self,content):
        messages=system_content.MESSAGES_FOR_KEYWORDS
        ai_info=self._generate_MPI(messages, content)
        return self._generate_text(messages=ai_info)
 
    def _generate_text(self,messages):
        
        completion = self.client.chat.completions.create(
            
            model=self.model,
            messages=messages,
        )
        return completion.choices[0].message.content
    

    def _generate_MPI(self, system_content, user_content):
        mpi = MessagePassingInterface(system_content=system_content, user_content=user_content)
        return mpi.to_dict
