import itertools
import requests
import json
from fastapi import Depends, FastAPI
from openai import OpenAI
from bs4 import BeautifulSoup
from ..auth.dependencies import session_opener
from ..auth.services import authenticate_user_token
from ..models import NewsArticle
from .utils import get_article_upvote_details, get_new_info, toggle_upvote
from .schemas import PromptRequest, NewsSumaryRequestSchema
from .config import GPT_MODEL, OPENAI_API_KEY
app = FastAPI()
@app.get("/api/v1/news/news")
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

@app.get("/api/v1/news/user_news")
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
@app.post("/api/v1/news/search_news")
async def search_news(request: PromptRequest):
    """
    :param request: `PromptRequest` 類型的請求對象，包含使用者輸入的新聞描述文字 (prompt)
    :return: JSON 格式的新聞列表
    """
    prompt = request.prompt
    news_list = []
    ai_info = [
        {
            "role": "system",
            "content": "你是一個關鍵字提取機器人，用戶將會輸入一段文字，表示其希望看見的新聞內容，請提取出用戶希望看見的關鍵字，請截取最重要的關鍵字即可，避免出現「新聞」、「資訊」等混淆搜尋引擎的字詞。(僅須回答關鍵字，若有多個關鍵字，請以空格分隔)",
        },
        {"role": "user", "content": f"{prompt}"},
    ]
    completion = OpenAI(api_key=OPENAI_API_KEY).chat.completions.create(
        model=GPT_MODEL,
        messages=ai_info,
    )
    keywords = completion.choices[0].message.content
    # should change into simple factory pattern
    news_items = get_new_info(keywords, is_initial=False)
    for news in news_items:
        try:
            response = requests.get(news["titleLink"])
            item_soup = BeautifulSoup(response.text, "html.parser")
            item_title = item_soup.find("h1", class_="article-content__title").text
            item_time = item_soup.find("time", class_="article-content__time").text
            # 定位到包含文章内容的 <section>
            content_section = item_soup.find("section", class_="article-content__editor")

            paragraphs = [
                paragraphinfo.text
                for paragraphinfo in content_section.find_all("p")
                if paragraphinfo.text.strip() != "" and "▪" not in paragraphinfo.text
            ]
            detailed_news = {
                "url": news["titleLink"],
                "title": item_title,
                "time": item_time,
                "content": paragraphs,
            }
            detailed_news["content"] = " ".join(detailed_news["content"])
            detailed_news["id"] = next(_id_counter)
            news_list.append(detailed_news)
        except Exception as error:
            print(error)
    return sorted(news_list, key=lambda x: x["time"], reverse=True)

@app.post("/api/v1/news/news_summary")
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
    ai_info = [
        {
            "role": "system",
            "content": "你是一個新聞摘要生成機器人，請統整新聞中提及的影響及主要原因 (影響、原因各50個字，請以json格式回答 {'影響': '...', '原因': '...'})",
        },
        {"role": "user", "content": f"{payload.content}"},
    ]
    completion = OpenAI(api_key=OPENAI_API_KEY).chat.completions.create(
        model=GPT_MODEL,
        messages=ai_info,
    )
    result = completion.choices[0].message.content
    if result:
        result = json.loads(result)
        response["summary"] = result["影響"]
        response["reason"] = result["原因"]
    return response

@app.post("/api/v1/news/{id}/upvote")
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