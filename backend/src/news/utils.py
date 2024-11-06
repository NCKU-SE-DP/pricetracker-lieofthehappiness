from sqlalchemy.orm import Session
from sqlalchemy import delete, insert, select
import json
from openai import OpenAI
from urllib.parse import quote
import requests
from bs4 import BeautifulSoup
from ..models import user_news_table, NewsArticle
from .config import GPT_MODEL, OPENAI_API_KEY, PAGES_INFO_URL

# def generate_summary(content):
#     ai_info = [
#         {
#             "role": "system",
#             "content": "你是一個新聞摘要生成機器人，請統整新聞中提及的影響及主要原因 (影響、原因各50個字，請以json格式回答 {'影響': '...', '原因': '...'})",
#         },
#         {"role": "user", "content": f"{content}"},
#     ]
#
#     completion = OpenAI(api_key=OPENAI_API_KEY).chat.completions.create(
#         model=GPT_MODEL,
#         messages=ai_info,
#     )
#     return completion.choices[0].message.content

#
# def extract_search_keywords(content):
#     ai_info = [
#         {
#             "role": "system",
#             "content": "你是一個關鍵字提取機器人，用戶將會輸入一段文字，表示其希望看見的新聞內容，請提取出用戶希望看見的關鍵字，請截取最重要的關鍵字即可，避免出現「新聞」、「資訊」等混淆搜尋引擎的字詞。(僅須回答關鍵字，若有多個關鍵字，請以空格分隔)",
#         },
#         {"role": "user", "content": f"{content}"},
#     ]
#
#     completion = OpenAI(api_key=OPENAI_API_KEY).chat.completions.create(
#         model=GPT_MODEL,
#         messages=ai_info,
#     )
#     return completion.choices[0].message.content

def add_new(news_data):
    """
    add new to db
    :param news_data: news info
    :return:
    """
    session = Session()
    session.add(NewsArticle(
        url=news_data["url"],
        title=news_data["title"],
        time=news_data["time"],
        content=" ".join(news_data["content"]),  # 將內容list轉換為字串
        summary=news_data["summary"],
        reason=news_data["reason"],
    ))
    session.commit()
    session.close()

def get_pages_info(search_term, page, channel_id=2):
    pageinfo = {
        "page": page,
        "id": f"search:{quote(search_term)}",
        "channelId": channel_id,
        "type": "searchword",
    }
    response = requests.get(PAGES_INFO_URL, params=pageinfo)
    response.raise_for_status() 
    return response.json().get("lists", [])

def get_new_info(search_term, is_initial=False):
    """
    根據搜尋詞獲取新聞文章
    :param search_term:關鍵字
    :param is_initial:是否獲取多個頁面的新聞資料
    :return:包含新聞資料的列表
    """
    all_news_info = []

    if is_initial:
        for pages in range(1, 10):
            page_info = get_pages_info(search_term, pages)
            all_news_info.extend(page_info)    
    else:
        all_news_info = get_pages_info(search_term, page=1)
    return all_news_info

def get_new(is_initial=False):
    """
    獲取並處理相關的新聞資料，並將符合條件的新聞存入資料庫
    :param is_initial:是否需要抓取多頁的新聞
    :return:
    """
    news_data = get_new_info("價格", is_initial=is_initial)
    for news in news_data:
        title = news["title"]
        ai_info = [
            {
                "role": "system",
                "content": "你是一個關聯度評估機器人，請評估新聞標題是否與「民生用品的價格變化」相關，並給予'high'、'medium'、'low'評價。(僅需回答'high'、'medium'、'low'三個詞之一)",
            },
            {"role": "user", "content": f"{title}"},
        ]
        ai = OpenAI(api_key=OPENAI_API_KEY).chat.completions.create(
            model=GPT_MODEL,
            messages=ai_info,
        )
        relevance = ai.choices[0].message.content
        if relevance == "high":
            response = requests.get(news["titleLink"])
            article_soup = BeautifulSoup(response.text, "html.parser")
            # 標題
            article_title = article_soup.find("h1", class_="article-content__title").text
            article_time = article_soup.find("time", class_="article-content__time").text
            # 定位到包含文章内容的 <section>
            content_section = article_soup.find("section", class_="article-content__editor")

            paragraphs = [
                paragraphinfo.text
                for paragraphinfo in content_section.find_all("p")
                if paragraphinfo.text.strip() != "" and "▪" not in paragraphinfo.text
            ]
            detailed_news =  {
                "url": news["titleLink"],
                "title":  article_title,
                "time": article_time,
                "content": paragraphs,
            }
            ai_info = [
                {
                    "role": "system",
                    "content": "你是一個新聞摘要生成機器人，請統整新聞中提及的影響及主要原因 (影響、原因各50個字，請以json格式回答 {'影響': '...', '原因': '...'})",
                },
                {"role": "user", "content": " ".join(detailed_news["content"])},
            ]

            completion = OpenAI(api_key=OPENAI_API_KEY).chat.completions.create(
                model=GPT_MODEL,
                messages=ai_info,
            )
            result = completion.choices[0].message.content
            result = json.loads(result)
            detailed_news["summary"] = result["影響"]
            detailed_news["reason"] = result["原因"]
            add_new(detailed_news)

def get_article_upvote_details(article_id, userid, db):
    """
    :param article_id: 
    :param userid: 
    :param db: 資料庫的 session
    :return: (點贊總數, 當前使用者是否已點贊)
    """
    total_upvotes = (
        db.query(user_news_table)
        .filter_by(news_articles_id=article_id)
        .count()
    )
    voted = False
    if userid:
        voted = (
                db.query(user_news_table)
                .filter_by(news_articles_id=article_id, user_id=userid)
                .first()
                is not None
        )
    return total_upvotes, voted

def toggle_upvote(articlesid, userid, db):
    """
    :param articlesid: 欲 upvote 或取消 upvote 的文章 ID。
    :param userid: 執行 upvote 操作的用戶 ID。
    :param db: 資料庫會話，用來執行查詢和操作。
    :return: "Upvote removed" 或 "Article upvoted" 字串，表示操作結果。
    """
    existing_upvote = db.execute(
        select(user_news_table).where(
            user_news_table.c.news_articles_id ==articlesid,
            user_news_table.c.user_id == userid,
        )
    ).scalar()

    if existing_upvote:
        delete_stmt = delete(user_news_table).where(
            user_news_table.c.news_articles_id == articlesid,
            user_news_table.c.user_id == userid,
        )
        db.execute(delete_stmt)
        db.commit()
        return "Upvote removed"
    else:
        insert_stmt = insert(user_news_table).values(
            news_articles_id=articlesid, user_id=userid
        )
        db.execute(insert_stmt)
        db.commit()
        return "Article upvoted"
    
def news_exists(article_id, db: Session):
    return db.query(NewsArticle).filter_by(id=article_id).first() is not None