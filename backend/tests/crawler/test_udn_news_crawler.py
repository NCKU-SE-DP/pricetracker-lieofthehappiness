import unittest
from unittest.mock import patch, MagicMock
from requests.models import Response
from sqlalchemy.orm import Session
from src.crawler.crawler_base import NewsWithSummary
from src.crawler.udn_crawler import UDNCrawler
from src.crawler.exceptions import (
    DomainMismatchException,
    InvalidSearchTermException,
    InvalidPageException,
    ParseException,
    SaveException
)
import requests
"""
這個測試檔案主要測試UDN爬蟲的各種功能和異常處理:

1. 基本功能測試:
- test_perform_request_success: 測試HTTP請求是否成功
- test_perform_request_failure: 測試HTTP請求失敗的處理
- test_fetch_news_data: 測試抓取新聞標題列表
- test_parse_news: 測試解析單篇新聞內容
- test_create_search_params: 測試建立搜尋參數
- test_save_news: 測試儲存新聞
- test_is_valid_url: 測試URL驗證

2. 異常處理測試:
- test_startup_empty_search_term: 測試空搜尋字串
- test_get_headline_empty_search_term: 測試空搜尋字串
- test_get_headline_invalid_page_number: 測試無效頁碼
- test_get_headline_invalid_page_range: 測試無效頁碼範圍
- test_perform_request_raises_parse_exception: 測試HTTP請求異常
- test_parse_headlines_raises_parse_exception: 測試解析標題異常
- test_parse_raises_parse_exception: 測試解析內容異常
- test_save_raises_save_exception: 測試儲存異常
- test_commit_changes_raises_save_exception: 測試資料庫提交異常
- test_parse_invalid_domain: 測試無效網域
"""

class TestUDNCrawler(unittest.TestCase):

    def setUp(self):
        self.scraper = UDNCrawler(timeout=5)

    @patch("src.crawler.udn_crawler.requests.get")
    def test_perform_request_success(self, mock_get):
        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        response = self.scraper._perform_request(params={"page": 1, "id": "search:technology"})
        self.assertEqual(response, mock_response)
        mock_get.assert_called_once()

    @patch("src.crawler.udn_crawler.requests.get")
    def test_perform_request_failure(self, mock_get):
        mock_get.side_effect = Exception("Network Error")
        with self.assertRaises(Exception):
            self.scraper._perform_request(params={"page": 1, "id": "search:technology"})

    @patch("src.crawler.udn_crawler.requests.get")
    def test_fetch_news_data(self, mock_get):
        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "lists": [{"title": "Test News", "titleLink": "https://udn.com/news/test-news"}]
        }
        mock_get.return_value = mock_response

        headlines = self.scraper._fetch_news_headline(page=1, search_term="technology")
        self.assertEqual(len(headlines), 1)
        self.assertEqual(headlines[0].title, "Test News")
        self.assertEqual(headlines[0].url, "https://udn.com/news/test-news")

    @patch("src.crawler.udn_crawler.requests.get")
    def test_parse_news(self, mock_get):
        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 200
        mock_response.text = """
            <html>
                <h1 class="article-content__title">Test Title</h1>
                <time class="article-content__time">2023-09-08T00:00:00</time>
                <section class="article-content__editor">
                    <p>Content paragraph 1.</p>
                    <p>Content paragraph 2.</p>
                </section>
            </html>
        """
        mock_get.return_value = mock_response

        news = self.scraper.parse("https://udn.com/news/test-news")
        self.assertEqual(news.title, "Test Title")
        self.assertEqual(news.time, "2023-09-08T00:00:00")
        self.assertEqual(news.content, "Content paragraph 1. Content paragraph 2.")

    def test_create_search_params(self):
        params = self.scraper._create_search_params(page=1, search_term="technology")
        self.assertEqual(params["page"], 1)
        self.assertEqual(params["id"], "search:technology")
        self.assertEqual(params["channelId"], 2)

    @patch("src.crawler.udn_crawler.Session")
    def test_save_news(self, mock_session):
        mock_db = MagicMock(spec=Session)
        mock_db.query.return_value.filter_by.return_value.first.return_value = None

        news = NewsWithSummary(
            title="Test Title",
            url="https://udn.com/news/test-news",
            time="2023-09-08T00:00:00",
            content="Test Content",
            summary="Test Summary",
            reason="Test Reason",
        )
        self.scraper.save(news, mock_db)

        mock_db.add.assert_called_once()
        self.assertEqual(mock_db.add.call_args[0][0].title, "Test Title")
        mock_db.commit.assert_called_once()

    def test_is_valid_url(self):
        valid_url = "https://udn.com/news/test-news"
        invalid_url = "https://example.com/news/test-news"

        self.assertTrue(self.scraper._is_valid_url(valid_url))
        self.assertFalse(self.scraper._is_valid_url(invalid_url))

    # 以下是異常處理的測試
    def test_startup_empty_search_term(self):
        with self.assertRaises(InvalidSearchTermException):
            self.scraper.startup("")

    def test_get_headline_empty_search_term(self):
        with self.assertRaises(InvalidSearchTermException):
            self.scraper.get_headline("", 1)

    def test_get_headline_invalid_page_number(self):
        with self.assertRaises(InvalidPageException):
            self.scraper.get_headline("test", -1)

    def test_get_headline_invalid_page_range(self):
        with self.assertRaises(InvalidPageException):
            self.scraper.get_headline("test", (2, 1)) 

    @patch("src.crawler.udn_crawler.requests.get")
    def test_perform_request_raises_parse_exception(self, mock_get):
        mock_get.side_effect = requests.RequestException("Network Error")
        with self.assertRaises(ParseException):
            self.scraper._perform_request(url="https://udn.com/news/test")

    @patch("src.crawler.udn_crawler.requests.get")
    def test_parse_headlines_raises_parse_exception(self, mock_get):
        mock_response = MagicMock(spec=Response)
        mock_response.json.side_effect = Exception("JSON Parse Error")
        mock_response.url = "https://udn.com/news/test"
        
        with self.assertRaises(ParseException):
            self.scraper._parse_headlines(mock_response)

    @patch("src.crawler.udn_crawler.requests.get")
    def test_parse_raises_parse_exception(self, mock_get):
        mock_response = MagicMock(spec=Response)
        mock_response.text = "<html></html>"  # 不完整的HTML
        mock_get.return_value = mock_response

        with self.assertRaises(ParseException):
            self.scraper.parse("https://udn.com/news/test")

    @patch("src.crawler.udn_crawler.Session")
    def test_save_raises_save_exception(self, mock_session):
        """測試當儲存新聞失敗時,應該拋出SaveException"""
        mock_db = MagicMock(spec=Session)
        mock_db.add.side_effect = Exception("Database Error")

        news = NewsWithSummary(
            title="Test Title",
            url="https://udn.com/news/test",
            time="2023-09-08T00:00:00",
            content="Test Content",
            summary="Test Summary",
            reason="Test Reason"
        )

        with self.assertRaises(SaveException):
            self.scraper.save(news, mock_db)

    @patch("src.crawler.udn_crawler.Session")
    def test_commit_changes_raises_save_exception(self, mock_session):
        """測試當提交資料庫變更失敗時,應該拋出SaveException並進行rollback"""
        mock_db = MagicMock(spec=Session)
        mock_db.commit.side_effect = Exception("Commit Error")

        with self.assertRaises(SaveException):
            self.scraper._commit_changes(mock_db)
        mock_db.rollback.assert_called_once()

    def test_parse_invalid_domain(self):
        """測試當URL不屬於UDN網域時,應該拋出DomainMismatchException"""
        invalid_url = "https://example.com/news/test-news"
        with self.assertRaises(DomainMismatchException):
            self.scraper.validate_and_parse(invalid_url)


if __name__ == "__main__":
    unittest.main()