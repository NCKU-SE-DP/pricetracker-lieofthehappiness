from fastapi import APIRouter, Depends, HTTPException
from ..database import session_opener
from ..auth.services import authenticate_user_token
from .schemas import PromptRequest, NewsSumaryRequestSchema
from ..crawler.udn_crawler import UDNCrawler
from ..crawler.crawler_base import NewsCrawlerBase
from . import services
from .schemas import NewsSumaryCustomModelSchema
from ..logger.base import logger
from sentry_sdk import capture_exception
from .exceptions import NewsSummaryException
udn_crawler=UDNCrawler()


router = APIRouter(
    prefix="/news",
    tags=["news"],
    responses={404: {"description": "Not found"}},
)
@router.get("/news")
def read_news(db=Depends(session_opener)):
    """
    獲取最新的新聞文章
    :param db:
    :return:包含新聞文章及其點贊詳情的列表
    """
    return services.read_news_with_details(db,None)

@router.get("/user_news")
def read_user_news(
        db=Depends(session_opener),
        usertoken=Depends(authenticate_user_token)
):
    """
    為使用者取得新聞文章，包含點讚詳情。
    :param db:
    :param usertoken:
    :return:包含點讚詳情的新聞文章列表
    """
    return services.read_news_with_details(db,usertoken)


@router.post("/search_news")
async def search_news(request: PromptRequest):
    """
    :param request: `PromptRequest` 類型的請求對象，包含使用者輸入的新聞描述文字 (prompt)
    :return: JSON 格式的新聞列表
    """
    return services.search_news(request)

@router.post("/news_summary")
async def news_summary(
        payload: NewsSumaryRequestSchema, user_token=Depends(authenticate_user_token)
):
    """
    這個 API 端點接收新聞內容，並生成一個包含新聞影響和原因的摘要
    :param payload: 包含新聞內容的請求數據
    :param user: 經由 `authenticate_user_token` 認證的使用者。
    :return: JSON 格式的摘要結果
    """
    return services.get_news_summary(payload,user_token,services.openai_client)

@router.post("/{article_id}/upvote")
def upvote_article(
        article_id,
        db=Depends(session_opener),
        usertoken=Depends(authenticate_user_token),
):
    """
    :param article_id:
    :param db:
    :param usertoken:
    :return: JSON 格式的點讚操作狀態訊息
    """
    return services.upvote_article(article_id,db,usertoken)

@router.post("/news_summary_custom_model")
async def summarize_news_with_custom_model(payload: NewsSumaryCustomModelSchema, user_token= Depends(authenticate_user_token)):
    llm_client = None
    if payload.llm_model == "anthropic":
        llm_client = services.anthropic_client
    elif payload.llm_model == "openai":
        llm_client = services.openai_client
    result = services.get_news_summary(payload,user_token,llm_client)
    return result

    

