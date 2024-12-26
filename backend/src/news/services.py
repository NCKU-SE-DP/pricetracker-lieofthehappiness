from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import delete, insert, select
import itertools
from ..models import user_news_table, NewsArticle
from ..logger.base import logger
from ..crawler.udn_crawler import UDNCrawler
from ..crawler.crawler_base import NewsWithSummary
from ..crawler.exceptions import ParseException
from ..llm_clients.openai_clients import OpenAIClient
from ..llm_clients.anthropic_clients import AnthropicClient
from ..llm_clients.exceptions import TextGenerationError
from .config import OPENAI_API_KEY, ANTHROPIC_KEY
from .exceptions import (
    NewsAddException,
    NewsSearchException,
    NewsServiceException,
    UpvoteException,
    UpvoteOperationException,
    NewsSummaryException,
)
from .router import PromptRequest
from sentry_sdk import capture_exception
import json

# 初始化客戶端
udn_crawler = UDNCrawler()
openai_client = OpenAIClient(api_key=OPENAI_API_KEY)
anthropic_client = AnthropicClient(api_key=ANTHROPIC_KEY)
_id_counter = itertools.count(start=1000000)
llm_client=OpenAIClient(api_key= OPENAI_API_KEY)

def search_news(request: PromptRequest):
    try:
        news_list = []
        keywords = llm_client.extract_search_keywords(request.prompt)
        news_items = get_new_info(keywords, is_initial=False)
        for news in news_items:
            try:
                detailed_news = udn_crawler.validate_and_parse(news.url).model_dump()
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
    
def read_news_with_details(db, usertoken):
    try:
        news = db.query(NewsArticle).order_by(NewsArticle.time.desc()).all()
        result = []
        for article in news:
            upvotes, upvoted = get_article_upvote_details(article.id, usertoken.id if usertoken else None, db)
            result.append(
                {**article.__dict__, "upvotes": upvotes, "is_upvoted": upvoted}
            )
        return result
    except Exception as e:
        logger.error(f"Failed to get news: {str(e)}")
        capture_exception(e)
        raise HTTPException(status_code=500, detail=str(e))

def add_new(news_data: NewsWithSummary):
    """
    add new to db
    :param news_data: news info
    :return:
    """
    try:
        session = Session()
        udn_crawler.save(news_data, session)
        session.close()
    except Exception as e:
        logger.error(f"Failed to add news: {str(e)}")
        capture_exception(e)
        raise NewsAddException(f"Failed to add news: {str(e)}")

def get_new_info(search_term, is_initial=False):
    """
    根據搜尋詞獲取新聞文章
    :param search_term:關鍵字
    :param is_initial:是否獲取多個頁面的新聞資料
    :return:包含新聞資料的列表
    """
    if is_initial:  
        return udn_crawler.get_headline(search_term,page=(1,10))    
    else:
        return udn_crawler.get_headline(search_term,1) 

def get_new(is_initial=False):
    """
    獲取並處理相關的新聞資料，並將符合條件的新聞存入資料庫
    :param is_initial:是否需要抓取多頁的新聞
    :return:
    """
    
    news_data = get_new_info("price", is_initial=is_initial)
    for news in news_data:
        title = news.title
        url=news.url
        relevance = openai_client.evaluate_relevance(title)
        if relevance == "high":
            news_from_crawler=udn_crawler.parse(url)
            result = openai_client.generate_summary(news_from_crawler.content)
            result = json.loads(result)
            detailed_news=NewsArticle(
                title=title,
                url=url,
                time=news_from_crawler.time,
                content=news_from_crawler.content,
                summary=result["影響"],
                reason=result["原因"]
            )
            add_new(detailed_news)


def get_article_upvote_details(article_id, userid, db):
    try:
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
    except Exception as e:
        logger.error(f"Failed to get upvote details: {str(e)}")
        capture_exception(e)
        raise UpvoteOperationException(f"Failed to get upvote details: {str(e)}")

def toggle_upvote(articlesid, userid, db):
    """
    :param articlesid: 欲 upvote 或取消 upvote 的文章 ID。
    :param userid: 執行 upvote 操作的用戶 ID。
    :param db: 資料庫會話，用來執行查詢和操作。
    :return: "Upvote removed" 或 "Article upvoted" 字串，表示操作結果。
    """
    try:
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
    except Exception as e:
        logger.error(f"Failed to perform upvote operation: {str(e)}")
        capture_exception(e)
        raise UpvoteOperationException(f"Failed to perform upvote operation: {str(e)}")
    
def news_exists(article_id, db: Session):
    try:
        return db.query(NewsArticle).filter_by(id=article_id).first() is not None
    except Exception as e:
        logger.error(f"Failed to check if news exists: {str(e)}")
        capture_exception(e)
        raise NewsServiceException(f"Failed to check if news exists: {str(e)}")
def upvote_article(article_id, db, usertoken):
    try:
        message = toggle_upvote(article_id, usertoken.id, db)
        return {"message": message}
    except Exception as e:
        logger.error(f"Failed to upvote: {str(e)}")
        capture_exception(e)
        raise UpvoteException(str(e))
def get_news_summary(payload,user_token,llm_client):
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
