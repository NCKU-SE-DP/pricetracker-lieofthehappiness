import abc
from pydantic import BaseModel, Field


class MessagePassingInterface(BaseModel):
    system_content: str = Field(...)
    user_content: str = Field(...)

    @property
    def to_dict(self) -> list[dict[str, str]]:
        dicts = [
            {"role": "system", "content": f"{self.system_content}"},
            {"role": "user", "content": f"{self.user_content}"}
        ]
        return dicts
    

class LLMClientBase(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def _generate_text(self,system_content:str, user_content:str) -> str:
        """
        Generate the response based on the system and user content.
        :param system_content: 
        :param user_content: 
        :return: 
        """
        return NotImplemented
