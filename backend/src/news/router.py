import itertools
import requests
import json
from fastapi import Depends
from ..database import session_opener
from ..auth.services import authenticate_user_token
from ..models import NewsArticle
from .services import get_article_upvote_details, get_new_info, toggle_upvote,openai_client, anthropic_client
from .schemas import PromptRequest, NewsSumaryRequestSchema, NewsSumaryCustomModelSchema
from fastapi import APIRouter
from ..crawler.udn_crawler import UDNCrawler


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
    news = db.query(NewsArticle).order_by(NewsArticle.time.desc()).all()
    result = []
    for article in news:
        upvotes, upvoted = get_article_upvote_details(article.id, None, db)
        result.append(
            {**article.__dict__, "upvotes": upvotes, "is_upvoted": upvoted}
        )
    return result

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

_id_counter = itertools.count(start=1000000)
@router.post("/search_news")
async def search_news(request: PromptRequest):
    """
    :param request: `PromptRequest` 類型的請求對象，包含使用者輸入的新聞描述文字 (prompt)
    :return: JSON 格式的新聞列表
    """
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
        except Exception as error:
            print(error)
    return sorted(news_list, key=lambda x: x["time"], reverse=True)

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
    response = {}
    result = llm_client.generate_summary(payload.content)
    if result:
        result = json.loads(result)
        response["summary"] = result["影響"]
        response["reason"] = result["原因"]
    return response

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
    message = toggle_upvote(article_id, usertoken.id, db)
    return {"message": message}
@router.post("/news_summary_custom_model")
async def summarize_news_with_custome_model(payload: NewsSumaryCustomModelSchema, user= Depends(authenticate_user_token)):
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
    