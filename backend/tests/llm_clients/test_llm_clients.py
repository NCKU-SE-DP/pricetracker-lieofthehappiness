import unittest
import os
from unittest.mock import patch

from src.llm_clients.openai_clients import OpenAIClient
from src.llm_clients.exceptions import MessageFormatError, TextGenerationError

# 除非確認要使用真實的API進行測試(當然會因此擁有額外的開銷)，否則將RUN_REAL_API_TESTS設置為False
RUN_REAL_API_TESTS = os.getenv("RUN_REAL_API_TESTS", "false").lower() == "true"


class TestOpenAIClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):  # 修正: self -> cls
        if RUN_REAL_API_TESTS:
            cls.client = OpenAIClient(api_key=os.getenv("OPENAI_API_KEY"))
        else:
            cls.client = OpenAIClient(api_key="fake_api_key")

    @unittest.skipIf(not RUN_REAL_API_TESTS, "模擬 API 呼叫，跳過真實測試")
    def test_evaluate_relevance_real(self):
        try:
            result = self.client.evaluate_relevance("食品價格上漲")
            self.assertIn(result, ["high", "medium", "low"])
        except Exception as e:
            self.fail(f"測試失敗，錯誤訊息: {str(e)}")

    @unittest.skipIf(not RUN_REAL_API_TESTS, "模擬 API 呼叫，跳過真實測試")
    def test_generate_summary_real(self):
        try:
            result = self.client.generate_summary("一篇有關食品價格的新聞內容")
            self.assertIn("影響", result)
            self.assertIn("原因", result)
        except Exception as e:
            self.fail(f"測試失敗，錯誤訊息: {str(e)}")

    @unittest.skipIf(not RUN_REAL_API_TESTS, "模擬 API 呼叫，跳過真實測試")
    def test_extract_search_keywords_real(self):
        try:
            result = self.client.extract_search_keywords("這篇新聞提到食品價格的波動以及市場的供應鏈問題")
            self.assertGreater(len(result.split()), 0)
        except Exception as e:
            self.fail(f"測試失敗，錯誤訊息: {str(e)}")

    @patch('src.llm_clients.openai_clients.OpenAIClient._generate_text')
    def test_evaluate_relevance(self, mock_generate_text):
        try:
            mock_generate_text.return_value = 'high'

            result = self.client.evaluate_relevance("食品價格上漲")

            self.assertEqual(result, 'high')

            mock_generate_text.assert_called_once()
        except Exception as e:
            self.fail(f"測試失敗，錯誤訊息: {str(e)}")

    @patch('src.llm_clients.Templete.LLMClientTemplate._generate_text')
    def test_generate_summary(self, mock_generate_text):
        try:
            mock_generate_text.return_value = '{"影響": "影響描述", "原因": "原因描述"}'
            result = self.client.generate_summary("一篇新聞內容")
            self.assertEqual(result, '{"影響": "影響描述", "原因": "原因描述"}')
            mock_generate_text.assert_called_once()
        except Exception as e:
            self.fail(f"測試失敗，錯誤訊息: {str(e)}")

    @patch('src.llm_clients.Templete.LLMClientTemplate._generate_text')
    def test_extract_search_keywords(self, mock_generate_text):
        try:
            mock_generate_text.return_value = '食品 價格'

            result = self.client.extract_search_keywords("一段希望看到的新聞文字")

            self.assertEqual(result, '食品 價格')
            mock_generate_text.assert_called_once()
        except Exception as e:
            self.fail(f"測試失敗，錯誤訊息: {str(e)}")

    # 測試 _generate_mpi_messages 方法在格式化訊息失敗時是否正確拋出 MessageFormatError
    def test_generate_mpi_messages_format_error(self):
        with self.assertRaises(MessageFormatError):
            self.client._generate_mpi_messages(system_content=None, user_content=None)


    def test_generate_text_error(self):
        with self.assertRaises(TextGenerationError):
            self.client._generate_text("", "")

    # 測試異常情況下的 evaluate_relevance 方法
    @patch('src.llm_clients.Templete.LLMClientTemplate._generate_text')
    def test_evaluate_relevance_error(self, mock_generate_text):
        mock_generate_text.side_effect = TextGenerationError("生成文字失敗")
        with self.assertRaises(TextGenerationError):
            self.client.evaluate_relevance("測試標題")

    # 測試異常情況下的 generate_summary 方法
    @patch('src.llm_clients.Templete.LLMClientTemplate._generate_text')
    def test_generate_summary_error(self, mock_generate_text):
        mock_generate_text.side_effect = TextGenerationError("生成摘要失敗")
        with self.assertRaises(TextGenerationError):
            self.client.generate_summary("測試內容")

    # 測試異常情況下的 extract_search_keywords 方法
    @patch('src.llm_clients.Templete.LLMClientTemplate._generate_text')
    def test_extract_search_keywords_error(self, mock_generate_text):
        mock_generate_text.side_effect = TextGenerationError("關鍵字提取失敗")
        with self.assertRaises(TextGenerationError):
            self.client.extract_search_keywords("測試內容")


if __name__ == '__main__':
    unittest.main()