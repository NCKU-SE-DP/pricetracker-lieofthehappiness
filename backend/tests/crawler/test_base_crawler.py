import unittest
from unittest.mock import patch, Mock
from pydantic import AnyHttpUrl
from src.crawler.crawler_base import NewsCrawlerBase, News, Headline
from src.crawler.exceptions import DomainMismatchException, ParseException, SaveException
from src.logger.base import logger


class MockNewsCrawler(NewsCrawlerBase):
    news_website_url = "https://www.example.com"
    news_website_news_child_urls = ["https://news.example.com"]

    def get_headline(self, search_term: str, page: int | tuple[int, int]):
        return [Headline(title="Test Article", url="https://www.example.com/article")]

    def parse(self, url: AnyHttpUrl | str):
        if url == "https://www.example.com/error":
            raise ParseException("測試解析錯誤")
        return News(
            title="Test Article",
            url=url,
            time="2023-09-08T00:00:00",
            content="This is the content of the article."
        )

    @staticmethod
    def save(news: News, db=None):
        if news.url == "https://www.example.com/save-error":
            raise SaveException("測試儲存錯誤")
        return True


class TestNewsCrawlerBase(unittest.TestCase):

    def setUp(self):
        self.crawler = MockNewsCrawler()

    def test_is_valid_url_valid(self):
        valid_url = "https://www.example.com/article"
        self.assertTrue(self.crawler._is_valid_url(valid_url))

    def test_is_valid_url_invalid(self):
        invalid_url = "https://www.invalid.com/article"
        self.assertFalse(self.crawler._is_valid_url(invalid_url))

    def test_is_valid_url_child(self):
        valid_child_url = "https://news.example.com/article"
        self.assertTrue(self.crawler._is_valid_url(valid_child_url))

    def test_validate_and_parse_raises_domain_mismatch(self):
        invalid_url = "https://www.invalid.com/article"
        with self.assertRaises(DomainMismatchException) as context:
            self.crawler.validate_and_parse(invalid_url)
        self.assertEqual(str(context.exception), DomainMismatchException(invalid_url).message)

    def test_parse_raises_parse_exception(self):
        error_url = "https://www.example.com/error"
        with self.assertRaises(ParseException) as context:
            self.crawler.parse(error_url)
        self.assertEqual(str(context.exception), "Failed to parse news content")

    def test_save_raises_save_exception(self):
        error_news = News(
            title="Test Article",
            url="https://www.example.com/save-error",
            time="2023-09-08T00:00:00",
            content="This is the content of the article."
        )
        with self.assertRaises(SaveException) as context:
            self.crawler.save(error_news)
        self.assertEqual(str(context.exception), "Failed to save news content")

    def test_validate_and_parse_logs_error(self):
        with patch.object(logger, 'error') as mock_logger:
            invalid_url = "https://www.invalid.com/article"
            with self.assertRaises(DomainMismatchException):
                self.crawler.validate_and_parse(invalid_url)
            mock_logger.assert_called_with(f"Error validating and parsing URL {invalid_url}: {DomainMismatchException(invalid_url)}")

    def test_get_headline(self):
        headlines = self.crawler.get_headline(search_term="test", page=1)
        self.assertEqual(len(headlines), 1)
        self.assertEqual(headlines[0].title, "Test Article")
        self.assertEqual(headlines[0].url, "https://www.example.com/article")

    def test_parse(self):
        news = self.crawler.parse("https://www.example.com/article")
        self.assertEqual(news.title, "Test Article")
        self.assertEqual(news.url, "https://www.example.com/article")
        self.assertEqual(news.time, "2023-09-08T00:00:00")
        self.assertEqual(news.content, "This is the content of the article.")

    @patch('src.crawler.crawler_base.Session')
    def test_save(self, mock_db_session):
        news = News(
            title="Test Article",
            url="https://www.example.com/article",
            time="2023-09-08T00:00:00",
            content="This is the content of the article."
        )
        result = self.crawler.save(news, mock_db_session)
        self.assertTrue(result)


if __name__ == '__main__':
    unittest.main()