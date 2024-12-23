"""
UDN News Scraper Module

This module provides the UDNCrawler class for fetching, parsing, and saving news articles from the UDN website.
The class extends the NewsCrawlerBase and includes functionalities to search for news articles based on a search term,
parse the details of individual articles, and save them to a database using SQLAlchemy ORM.

Classes:
    UDNCrawler: A class to scrape news from UDN.

Exceptions:
    DomainMismatchException: Raised when the URL domain does not match the expected domain for the crawler.

Usage Example:
    crawler = UDNCrawler(timeout=10)
    headlines = crawler.startup("technology")
    for headline in headlines:
        news = crawler.parse(headline.url)
        crawler.save(news, db_session)

UDNCrawler Methods:
    __init__(self, timeout: int = 5): Initializes the crawler with a default timeout for HTTP requests.
    startup(self, search_term: str) -> list[Headline]: Fetches news headlines for a given search term across multiple pages.
    get_headline(self, search_term: str, page: int | tuple[int, int]) -> list[Headline]: Fetches news headlines for specified pages.
    _fetch_news(self, page: int, search_term: str) -> list[Headline]: Helper method to fetch news headlines for a specific page.
    _create_search_params(self, page: int, search_term: str): Creates the parameters for the search request.
    _perform_request(self, params: dict): Performs the HTTP request to fetch news data.
    _parse_headlines(response): Parses the response to extract headlines.
    parse(self, url: str) -> News: Parses a news article from a given URL.
    _extract_news(soup, url: str) -> News: Extracts news details from the BeautifulSoup object.
    save(self, news: News, db: Session): Saves a news article to the database.
    _commit_changes(db: Session): Commits the changes to the database with error handling.
"""

import logging
from sentry_sdk import capture_exception
import requests
from bs4 import BeautifulSoup
from sqlalchemy.orm import Session
from urllib.parse import quote
from .crawler_base import NewsCrawlerBase, Headline, News, NewsWithSummary
from requests import Response
from .exceptions import InvalidSearchTermException, InvalidPageException, ParseException, SaveException
from ..logger.base import logger

class Page:
    def __init__(self, page: int, search_term: str, channel_id: str) -> None:
        self.page = page
        self.search_term = search_term
        self.channel_id = channel_id
        self.type="searchword"
    def to_dict(self) -> dict:
        """Convert the Page instance into a dictionary."""
        return {
            "page": self.page,
            "id": f"search:{quote(self.search_term)}",
            "channelId": self.channel_id,
            "type": "searchword",
        }

class UDNCrawler(NewsCrawlerBase):
    CHANNEL_ID = 2

    def __init__(self, timeout: int = 5) -> None:
        self.news_website_url = "https://udn.com/api/more"
        self.timeout = timeout

    def startup(self, search_term: str) -> list[Headline]:
        """
        Initializes the application by fetching news headlines for a given search term across multiple pages.
        This method is typically called at the beginning of the program when there is no data available,
        hence it fetches headlines from the first 10 pages.

        :param search_term: The term to search for in news headlines.
        :return: A list of Headline namedtuples containing the title and URL of news articles.
        :rtype: list[Headline]
        """
        if not search_term:
            logger.error(f"Invalid search term: {search_term}")
            raise InvalidSearchTermException(search_term)
        logger.info(f"Starting up crawler with search term: {search_term}")
        return self.get_headline(search_term, page=(1, 10))

    def get_headline(
        self, search_term: str, page: int | tuple[int, int]
    ) -> list[Headline]:
        if not search_term:
            logger.error(f"Invalid search term: {search_term}")
            raise InvalidSearchTermException(search_term)
            
        if isinstance(page, tuple) and (page[0] < 0 or page[1] < page[0]):
            logger.error(f"Invalid page range: {page}")
            raise InvalidPageException(page)
        elif isinstance(page, int) and page < 0:
            logger.error(f"Invalid page number: {page}")
            raise InvalidPageException(page)

        # Calculate the range of pages to fetch news from.
        # If 'page' is a tuple, unpack it and create a range representing those pages (inclusive).
        # If 'page' is an int, create a list containing only that single page number.
        page_range = range(*page) if isinstance(page, tuple) else [page]
        headlines = []
        for page_number in page_range:
            logger.info(f"Fetching headlines for page {page_number}")
            headlines.extend(self._fetch_news_headline(page_number, search_term))
        return headlines 

    def _fetch_news_headline(self, page: int, search_term: str) -> list[Headline]:
        newsinfo=self._perform_request(self.news_website_url, self._create_search_params(page, search_term))
        return self._parse_headlines(newsinfo)
    
    def _create_search_params(self, page: int, search_term: str) -> dict:
        pageinfo=Page(page, search_term, self.CHANNEL_ID)
        return pageinfo.to_dict()
         
    def _perform_request(self, url: str | None = None, params: dict | None = None) -> Response:
        try:
            response = requests.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response
        except requests.RequestException as e:
            logger.error(f"Request failed for URL {url}: {str(e)}")
            capture_exception(e)
            raise ParseException(url=url, message=str(e))

    @staticmethod
    def _parse_headlines(response: Response) -> list[Headline]:
        list_of_headline=[]
        try:
            news_list=response.json().get("lists", [])
            for news in news_list:
                headline=Headline(title=news["title"], url=news["titleLink"])
                list_of_headline.append(headline)
            logger.info(f"Successfully parsed {len(list_of_headline)} headlines")
            return list_of_headline
        except Exception as e:
            logger.error(f"Failed to parse headlines from {response.url}: {str(e)}")
            capture_exception(e)
            raise ParseException(url=response.url, message=str(e))

    def parse(self, url: str) -> News:
        try:
            response=self._perform_request(url=url)
            soup=BeautifulSoup(response.text, "html.parser")
            news=self._extract_news(soup, url)
            logger.info(f"Successfully parsed news from {url}")
            return news
        except Exception as e:
            logger.error(f"Failed to parse news from {url}: {str(e)}")
            capture_exception(e)
            raise ParseException(url=url, message=str(e))

    @staticmethod
    def _extract_news(soup: BeautifulSoup, url: str) -> News:
        try:
            title = soup.find("h1", class_="article-content__title").text
            time = soup.find("time", class_="article-content__time").text
            content_section = soup.find("section", class_="article-content__editor")
            paragraphs = [
                paragraphinfo.text
                for paragraphinfo in content_section.find_all("p")
                if paragraphinfo.text.strip() != "" and "▪" not in paragraphinfo.text
            ]
            content = " ".join(paragraphs)
            news=News(
                title=title,
                url=url,
                time=time,
                content=content
            )
            return news
        except Exception as e:
            logger.error(f"Failed to extract news content from {url}: {str(e)}")
            capture_exception(e)
            raise ParseException(url=url, message=str(e))

    def save(self, news_data: NewsWithSummary, db: Session):
        try:
            db.add(news_data)
            self._commit_changes(db)
            logger.info(f"Successfully saved news: {news_data.title}")
        except Exception as e:
            logger.error(f"Failed to save news {news_data.title}: {str(e)}")
            capture_exception(e)
            raise SaveException(news=news_data, message=str(e))

    @staticmethod
    def _commit_changes(db: Session):
        try:
            db.commit()
            logger.info("Successfully committed changes to database")
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to commit changes to database: {str(e)}")
            capture_exception(e)
            raise SaveException(news=None, message=str(e))