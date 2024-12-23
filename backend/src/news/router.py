import itertools
import requests
import json
from fastapi import Depends, HTTPException
from ..database import session_opener
from ..auth.services import authenticate_user_token
from ..models import NewsArticle
from .services import get_article_upvote_details, get_new_info, toggle_upvote,openai_client, anthropic_client
from .schemas import PromptRequest, NewsSumaryRequestSchema, NewsSumaryCustomModelSchema
from fastapi import APIRouter
from ..crawler.udn_crawler import UDNCrawler
from ..crawler.exceptions import ParseException
from ..llm_clients.exceptions import TextGenerationError
from .exceptions import NewsSearchException, NewsSummaryException, UpvoteException
from ..logger.base import logger
from sentry_sdk import capture_exception
from .exceptions import NewsSummaryException, UpvoteException


udn_crawler=UDNCrawler()
llm_client=openai_client

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
    try:
        news = db.query(NewsArticle).order_by(NewsArticle.time.desc()).all()
        result = []
        for article in news:
            upvotes, upvoted = get_article_upvote_details(article.id, None, db)
            result.append(
                {**article.__dict__, "upvotes": upvotes, "is_upvoted": upvoted}
            )
        return result
    except Exception as e:
        logger.error(f"Failed to get news: {str(e)}")
        capture_exception(e)
        raise HTTPException(status_code=500, detail=str(e))

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
    try:
        news = db.query(NewsArticle).order_by(NewsArticle.time.desc()).all()
        result = []
        for article in news:
            upvotes, upvoted = get_article_upvote_details(article.id, usertoken.id, db)
            result.append(
                {
                    **article.__dict__,
                    "upvotes": upvotes,
                    "is_upvoted": upvoted,
                }
            )
        return result
    except Exception as e:
        logger.error(f"Failed to get user news: {str(e)}")
        capture_exception(e)
        raise HTTPException(status_code=500, detail=str(e))

_id_counter = itertools.count(start=1000000)
@router.post("/search_news")
async def search_news(request: PromptRequest):
    """
    :param request: `PromptRequest` 類型的請求對象，包含使用者輸入的新聞描述文字 (prompt)
    :return: JSON 格式的新聞列表
    """
    try:
        news_list = []
        keywords = llm_client.extract_search_keywords(request.prompt)
        news_items = get_new_info(keywords, is_initial=False)
        for news in news_items:
            try:
                news_from_crawler=udn_crawler.parse(news.url)
                content = news_from_crawler.content
               
                detailed_news = {
                    "url": news.url,
                    "title": news.title,
                    "time": news_from_crawler.time,
                    "content": content,
                }
                detailed_news["id"]  = next(_id_counter)

                news_list.append(detailed_news)
            except ParseException as error:
                logger.error(f"Failed to parse news: {str(error)}")
                capture_exception(error)
                continue
        return sorted(news_list, key=lambda x: x["time"], reverse=True)
    except TextGenerationError as e:
        logger.error(f"Failed to extract keywords: {str(e)}")
        capture_exception(e)
        raise NewsSearchException(f"Failed to extract keywords: {str(e)}")
    except Exception as e:
        logger.error(f"Failed to search news: {str(e)}")
        capture_exception(e)
        raise NewsSearchException(str(e))

@router.post("/news_summary")
async def news_summary(
        payload: NewsSumaryRequestSchema, user=Depends(authenticate_user_token)
):
    """
    這個 API 端點接收新聞內容，並生成一個包含新聞影響和原因的摘要
    :param payload: 包含新聞內容的請求數據
    :param user: 經由 `authenticate_user_token` 認證的使用者。
    :return: JSON 格式的摘要結果
    """
    try:
        response = {}
        result = llm_client.generate_summary(payload.content)
        if result:
            result = json.loads(result)
            response["summary"] = result["影響"]
            response["reason"] = result["原因"]
        return response
    except TextGenerationError as e:
        logger.error(f"Failed to generate summary: {str(e)}")
        capture_exception(e)
        raise NewsSummaryException(f"Failed to generate summary: {str(e)}")
    except json.JSONDecodeError as e:
        logger.error(f"Invalid summary format: {str(e)}")
        capture_exception(e)
        raise NewsSummaryException("Invalid summary format")
    except Exception as e:
        logger.error(f"Error occurred during summary generation: {str(e)}")
        capture_exception(e)
        raise NewsSummaryException(str(e))

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
    try:
        message = toggle_upvote(article_id, usertoken.id, db)
        return {"message": message}
    except Exception as e:
        logger.error(f"Failed to upvote: {str(e)}")
        capture_exception(e)
        raise UpvoteException(str(e))

@router.post("/news_summary_custom_model")
async def summarize_news_with_custome_model(payload: NewsSumaryCustomModelSchema, user= Depends(authenticate_user_token)):
    try:
        response = {}
        if(payload.ai_model=="anthropic") :
            llm_client=anthropic_client
        if(payload.ai_model=="openai") :
            llm_client=openai_client 
        result = llm_client.generate_summary(payload.content)
        if result:
            result = json.loads(result)
            response["summary"] = result["影響"]
            response["reason"] = result["原因"]
        return response
    except TextGenerationError as e:
        logger.error(f"Custom model failed to generate summary: {str(e)}")
        capture_exception(e)
        raise NewsSummaryException(f"Failed to generate summary: {str(e)}")
    except json.JSONDecodeError as e:
        logger.error(f"Custom model invalid summary format: {str(e)}")
        capture_exception(e)
        raise NewsSummaryException("Invalid summary format")
    except Exception as e:
        logger.error(f"Error occurred during custom model summary generation: {str(e)}")
        capture_exception(e)
        raise NewsSummaryException(str(e))

@router.get("/sentry-debug")
async def trigger_error():
    division_by_zero = 1 / 0