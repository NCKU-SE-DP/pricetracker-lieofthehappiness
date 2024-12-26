from pydantic import BaseModel
from typing import Literal
class PromptRequest(BaseModel):
    prompt: str
class NewsSumaryRequestSchema(BaseModel):
    content: str
class NewsSumaryCustomModelSchema(BaseModel):
    content: str
    llm_model: Literal["openai", "anthropic"]