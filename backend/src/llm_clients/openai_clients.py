from .openai_clients_base import MessagePassingInterface, LLMClientBase
from openai import OpenAI
from .messages import System_content
from .config import OPENAI_API_KEY, GPT_MODEL

class OpenAIClient(LLMClientBase):
    
    def __init__(self, _api_key: str):
        try:
            OpenAI.api_key = _api_key
            self.openai_client = OpenAI
            # self.openai_client = OpenAI(api_key=_api_key)
        except Exception as error:
            raise ValueError(f"Failed to initialize OpenAI client: {error}")
    def evaluate_relevance(self, title):
        messages=System_content.messages_for_relevance()
        ai_info=self.generate_MPI(messages, title)
        return self._generate_text(messages=ai_info)

    def generate_summary(self, content):
        messages=System_content.messages_for_generte_summary()
        ai_info=self.generate_MPI(messages, content)
        return self._generate_text(messages=ai_info)

    def extract_search_keywords(self,content):
        messages=System_content.messages_for_keywords()
        ai_info=self.generate_MPI(messages, content)
        return self._generate_text(messages=ai_info)
    
    def _generate_text(self,messages):
        completion = OpenAI(api_key=OPENAI_API_KEY).chat.completions.create(
            model=GPT_MODEL,
            messages=messages,
        )
        return completion.choices[0].message.content
    
    def generate_MPI(self,system_content, user_content):
        MPI=MessagePassingInterface(system_content=system_content, user_content=user_content)
        return MPI.to_dict







