import os
from sentry_sdk import capture_message
from ..logger.base import logger
from dotenv import load_dotenv
load_dotenv()
GPT_MODEL = "gpt-3.5-turbo"
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
ANTHROPIC_KEY = os.getenv("ANTHROPIC_API_KEY") 
PAGES_INFO_URL = "https://udn.com/api/more"