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

class NewsSearchException(Exception):
    """搜尋新聞時發生錯誤"""
    def __init__(self, message: str = "搜尋新聞失敗"):
        self.message = message
        super().__init__(self.message)

class NewsSummaryException(Exception):
    """生成新聞摘要時發生錯誤"""
    def __init__(self, message: str = "生成新聞摘要失敗"):
        self.message = message
        super().__init__(self.message)

class UpvoteException(Exception):
    """點讚操作失敗"""
    def __init__(self, message: str = "點讚操作失敗"):
        self.message = message
        super().__init__(self.message)

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
                print(f"解析新聞失敗: {error}")
                continue
        return sorted(news_list, key=lambda x: x["time"], reverse=True)
    except TextGenerationError as e:
        raise NewsSearchException(f"關鍵字提取失敗: {str(e)}")
    except Exception as e:
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
        raise NewsSummaryException(f"生成摘要失敗: {str(e)}")
    except json.JSONDecodeError:
        raise NewsSummaryException("摘要格式錯誤")
    except Exception as e:
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
        raise NewsSummaryException(f"生成摘要失敗: {str(e)}")
    except json.JSONDecodeError:
        raise NewsSummaryException("摘要格式錯誤")
    except Exception as e:
        raise NewsSummaryException(str(e))

@router.get("/sentry-debug")
async def trigger_error():
    division_by_zero = 1 / 0  